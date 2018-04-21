/*
 * Copyright (C) 2018 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { DeploymentError, NotFoundError } from "../../exceptions"
import { Environment } from "../../types/common"
import {
  ConfigureEnvironmentParams, DeleteConfigParams,
  DestroyEnvironmentParams,
  ExecInServiceParams, GetConfigParams,
  GetEnvironmentStatusParams,
  GetServiceLogsParams,
  GetServiceOutputsParams,
  GetServiceStatusParams, GetTestResultParams,
  SetConfigParams,
  TestModuleParams, TestResult,
} from "../../types/plugin"
import { TreeVersion } from "../../vcs/base"
import {
  ContainerModule,
} from "../container"
import { values, every, map, extend } from "lodash"
import { deserializeKeys, serializeKeys, splitFirst } from "../../util"
import { ServiceStatus } from "../../types/service"
import {
  apiGetOrNull,
  apiPostOrPut,
  coreApi,
} from "./api"
import {
  createNamespace,
  getAppNamespace,
  getMetadataNamespace,
} from "./namespace"
import {
  kubectl,
} from "./kubectl"
import { DEFAULT_TEST_TIMEOUT } from "../../constants"
import * as split from "split"
import moment = require("moment")
import { EntryStyle } from "../../logger/types"
import {
  checkDeploymentStatus,
} from "./status"
import {
  getSystemGarden,
  isSystemGarden,
} from "./system"

export function getContext(env: Environment) {
  // TODO: would be nicer to extract and pass the providerConfig implicitly to handler functions
  return env.config.providers.kubernetes!.context
}

export async function getEnvironmentStatus({ ctx, env }: GetEnvironmentStatusParams) {
  const context = getContext(env)

  try {
    // TODO: use API instead of kubectl (I just couldn't find which API call to make)
    await kubectl(context).call(["version"])
  } catch (err) {
    // TODO: catch error properly
    if (err.output) {
      throw new DeploymentError(err.output, { output: err.output })
    }
    throw err
  }

  const statusDetail: { [key: string]: boolean } = {
    namespaceReady: false,
    metadataNamespaceReady: false,
  }

  if (!isSystemGarden(ctx)) {
    const sysGarden = await getSystemGarden(env)
    const sysStatus = await sysGarden.pluginContext.getStatus()

    statusDetail.systemReady = sysStatus.providers.kubernetes.configured &&
      every(values(sysStatus.services).map(s => s.state === "ready"))
  }

  const metadataNamespace = getMetadataNamespace(ctx)
  const namespacesStatus = await coreApi(context).namespaces().get()

  for (const n of namespacesStatus.items) {
    if (n.metadata.name === getAppNamespace(ctx, env) && n.status.phase === "Active") {
      statusDetail.namespaceReady = true
    }

    if (n.metadata.name === metadataNamespace && n.status.phase === "Active") {
      statusDetail.metadataNamespaceReady = true
    }
  }

  let configured = every(values(statusDetail))

  return {
    configured,
    detail: statusDetail,
  }
}

export async function configureEnvironment({ ctx, config, env, logEntry }: ConfigureEnvironmentParams) {
  // TODO: use Helm 3 when it's released instead of this custom/manual stuff
  const status = await getEnvironmentStatus({ ctx, config, env })

  if (status.configured) {
    return
  }

  const context = getContext(env)

  if (isSystemGarden(ctx)) {
    const sysGarden = await getSystemGarden(env)
    await configureEnvironment({
      ctx: sysGarden.pluginContext,
      env: sysGarden.getEnvironment(),
      config: {},
      logEntry,
    })
    await sysGarden.pluginContext.deployServices({ logEntry })
  }

  if (!status.detail.namespaceReady) {
    const ns = getAppNamespace(ctx, env)
    logEntry && logEntry.setState({ section: "kubernetes", msg: `Creating namespace ${ns}` })
    await createNamespace(context, ns)
  }

  if (!status.detail.metadataNamespaceReady) {
    const ns = getMetadataNamespace(ctx)
    logEntry && logEntry.setState({ section: "kubernetes", msg: `Creating namespace ${ns}` })
    await createNamespace(context, ns)
  }
}

export async function getServiceStatus(
  { ctx, env, service }: GetServiceStatusParams<ContainerModule>,
): Promise<ServiceStatus> {
  // TODO: hash and compare all the configuration files (otherwise internal changes don't get deployed)
  return await checkDeploymentStatus({ ctx, env, service })
}

export async function destroyEnvironment({ ctx, env }: DestroyEnvironmentParams) {
  const context = getContext(env)
  const namespace = getAppNamespace(ctx, env)
  const entry = ctx.log.info({
    section: "kubernetes",
    msg: `Deleting namespace ${namespace}`,
    entryStyle: EntryStyle.activity,
  })
  try {
    await coreApi(context).namespace(namespace).delete(namespace)
    entry.setSuccess("Finished")
  } catch (err) {
    entry.setError(err.message)
    throw new NotFoundError(err, { namespace })
  }
}

export async function getServiceOutputs({ service }: GetServiceOutputsParams<ContainerModule>) {
  return {
    host: service.name,
  }
}

export async function execInService({ ctx, config, service, env, command }: ExecInServiceParams<ContainerModule>) {
  const context = getContext(env)
  const status = await getServiceStatus({ ctx, config, service, env })
  const namespace = getAppNamespace(ctx, env)

  // TODO: this check should probably live outside of the plugin
  if (!status.state || status.state !== "ready") {
    throw new DeploymentError(`Service ${service.name} is not running`, {
      name: service.name,
      state: status.state,
    })
  }

  // get a running pod
  let res = await coreApi(context, namespace).namespaces.pods.get({
    qs: {
      labelSelector: `service=${service.name}`,
    },
  })
  const pod = res.items[0]

  if (!pod) {
    // This should not happen because of the prior status check, but checking to be sure
    throw new DeploymentError(`Could not find running pod for ${service.name}`, {
      serviceName: service.name,
    })
  }

  // exec in the pod via kubectl
  res = await kubectl(context, namespace).tty(["exec", "-it", pod.metadata.name, "--", ...command])

  return { code: res.code, output: res.output }
}

export async function testModule(
  { ctx, env, module, testName, testSpec }: TestModuleParams<ContainerModule>,
): Promise<TestResult> {
  // TODO: include a service context here
  const context = getContext(env)
  const baseEnv = {}
  const envVars: {} = extend({}, baseEnv, testSpec.variables)
  const envArgs = map(envVars, (v: string, k: string) => `--env=${k}=${v}`)

  // TODO: use the runModule() method
  const testCommandStr = testSpec.command.join(" ")
  const image = await module.getLocalImageId()
  const version = await module.getVersion()

  const kubecmd = [
    "run", `run-${module.name}-${Math.round(new Date().getTime())}`,
    `--image=${image}`,
    "--restart=Never",
    "--command",
    "-i",
    "--tty",
    "--rm",
    ...envArgs,
    "--",
    "/bin/sh",
    "-c",
    testCommandStr,
  ]

  const startedAt = new Date()

  const timeout = testSpec.timeout || DEFAULT_TEST_TIMEOUT
  const res = await kubectl(context, getAppNamespace(ctx, env)).tty(kubecmd, { ignoreError: true, timeout })

  const testResult: TestResult = {
    moduleName: module.name,
    testName,
    version,
    success: res.code === 0,
    startedAt,
    completedAt: new Date(),
    output: res.output,
  }

  const ns = getMetadataNamespace(ctx)
  const resultKey = getTestResultKey(module, testName, version)
  const body = {
    body: {
      apiVersion: "v1",
      kind: "ConfigMap",
      metadata: {
        name: resultKey,
        annotations: {
          "garden.io/generated": "true",
        },
      },
      type: "generic",
      data: serializeKeys(testResult),
    },
  }

  await apiPostOrPut(coreApi(context, ns).namespaces.configmaps, resultKey, body)

  return testResult
}

export async function getTestResult({ ctx, env, module, testName, version }: GetTestResultParams<ContainerModule>) {
  const context = getContext(env)
  const ns = getMetadataNamespace(ctx)
  const resultKey = getTestResultKey(module, testName, version)
  const res = await apiGetOrNull(coreApi(context, ns).namespaces.configmaps, resultKey)
  return res && <TestResult>deserializeKeys(res.data)
}

export async function getServiceLogs({ ctx, env, service, stream, tail }: GetServiceLogsParams<ContainerModule>) {
  const context = getContext(env)
  const resourceType = service.config.daemon ? "daemonset" : "deployment"

  const kubectlArgs = ["logs", `${resourceType}/${service.name}`, "--timestamps=true"]

  if (tail) {
    kubectlArgs.push("--follow")
  }

  const proc = kubectl(context, getAppNamespace(ctx, env)).spawn(kubectlArgs)

  proc.stdout
    .pipe(split())
    .on("data", (s) => {
      if (!s) {
        return
      }
      const [timestampStr, msg] = splitFirst(s, " ")
      const timestamp = moment(timestampStr)
      stream.write({ serviceName: service.name, timestamp, msg })
    })

  proc.stderr.pipe(process.stderr)

  return new Promise<void>((resolve, reject) => {
    proc.on("error", reject)

    proc.on("exit", () => {
      resolve()
    })
  })
}

export async function getConfig({ ctx, env, key }: GetConfigParams) {
  const context = getContext(env)
  const ns = getMetadataNamespace(ctx)
  const res = await apiGetOrNull(coreApi(context, ns).namespaces.secrets, key.join("."))
  return res && Buffer.from(res.data.value, "base64").toString()
}

export async function setConfig({ ctx, env, key, value }: SetConfigParams) {
  // we store configuration in a separate metadata namespace, so that configs aren't cleared when wiping the namespace
  const context = getContext(env)
  const ns = getMetadataNamespace(ctx)
  const body = {
    body: {
      apiVersion: "v1",
      kind: "Secret",
      metadata: {
        name: key,
        annotations: {
          "garden.io/generated": "true",
        },
      },
      type: "generic",
      stringData: { value },
    },
  }

  await apiPostOrPut(coreApi(context, ns).namespaces.secrets, key.join("."), body)
}

export async function deleteConfig({ ctx, env, key }: DeleteConfigParams) {
  const context = getContext(env)
  const ns = getMetadataNamespace(ctx)
  try {
    await coreApi(context, ns).namespaces.secrets(key.join(".")).delete()
  } catch (err) {
    if (err.code === 404) {
      return { found: false }
    } else {
      throw err
    }
  }
  return { found: true }
}

function getTestResultKey(module: ContainerModule, testName: string, version: TreeVersion) {
  return `test-result--${module.name}--${testName}--${version.versionString}`
}
