/*
 * Copyright (C) 2018 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import * as execa from "execa"
import { safeLoad } from "js-yaml"
import {
  every,
  values,
} from "lodash"
import * as Joi from "joi"
import { join } from "path"
import { PluginError } from "../../exceptions"
import { Environment, validate } from "../../config/common"
import {
  GardenPlugin,
} from "../../types/plugin/plugin"
import {
  ConfigureEnvironmentParams,
  GetEnvironmentStatusParams,
} from "../../types/plugin/params"
import { providerConfigBase } from "../../config/project"
import { findByName } from "../../util/util"
import {
  configureEnvironment,
  getEnvironmentStatus,
} from "./actions"
import {
  gardenPlugin as k8sPlugin,
  KubernetesConfig,
  KubernetesProvider,
} from "./kubernetes"
import {
  getSystemGarden,
  isSystemGarden,
} from "./system"
import { readFile } from "fs-extra"
import { LogEntry } from "../../logger/logger"
import { homedir } from "os"
import { helm } from "./helm"

// TODO: split this into separate plugins to handle Docker for Mac and Minikube

// note: this is in order of preference, in case neither is set as the current kubectl context
// and none is explicitly configured in the garden.yml
const supportedContexts = ["docker-for-desktop", "minikube"]
const kubeConfigPath = join(homedir(), ".kube", "config")

// extend the environment configuration to also set up an ingress controller and dashboard
export async function getLocalEnvironmentStatus(
  { ctx, provider, env, logEntry }: GetEnvironmentStatusParams,
) {
  const status = await getEnvironmentStatus({ ctx, provider, env, logEntry })

  if (!isSystemGarden(provider)) {
    const sysGarden = await getSystemGarden(provider)
    const sysStatus = await sysGarden.getPluginContext().getStatus()

    status.detail.systemReady = sysStatus.providers[provider.name].configured &&
      every(values(sysStatus.services).map(s => s.state === "ready"))
    // status.detail.systemServicesStatus = sysStatus.services
  }

  status.configured = every(values(status.detail))

  return status
}

async function configureSystemEnvironment(
  { provider, env, force, logEntry }:
    { provider: KubernetesProvider, env: Environment, force: boolean, logEntry?: LogEntry },
) {
  const sysGarden = await getSystemGarden(provider)
  const sysCtx = sysGarden.getPluginContext()
  const sysProvider: KubernetesProvider = {
    name: provider.name,
    config: <KubernetesConfig>findByName(sysGarden.environmentConfig.providers, provider.name)!,
  }

  // TODO: need to add logic here to wait for tiller to be ready
  await helm(sysProvider,
    "init", "--wait",
    "--service-account", "default",
    "--upgrade",
  )

  const sysStatus = await getEnvironmentStatus({
    ctx: sysCtx,
    provider: sysProvider,
    env,
  })

  await configureEnvironment({
    ctx: sysCtx,
    env: sysGarden.getEnvironment(),
    provider: sysProvider,
    force,
    status: sysStatus,
    logEntry,
  })

  const results = await sysCtx.deployServices({})

  const failed = values(results.taskResults).filter(r => !!r.error).length

  if (failed) {
    throw new PluginError(`local-kubernetes: ${failed} errors occurred when configuring environment`, {
      results,
    })
  }
}

async function configureLocalEnvironment(
  { ctx, provider, env, force, status, logEntry }: ConfigureEnvironmentParams,
) {
  await configureEnvironment({ ctx, provider, env, force, status, logEntry })

  if (!isSystemGarden(provider)) {
    await configureSystemEnvironment({ provider, env, force, logEntry })
  }

  return {}
}

async function getKubeConfig(): Promise<any> {
  try {
    return safeLoad((await readFile(kubeConfigPath)).toString())
  } catch {
    return {}
  }
}

/**
 * Automatically set docker environment variables for minikube
 * TODO: it would be better to explicitly provide those to docker instead of using process.env
 */
async function setMinikubeDockerEnv() {
  const minikubeEnv = await execa.stdout("minikube", ["docker-env", "--shell=bash"])
  for (const line of minikubeEnv.split("\n")) {
    const matched = line.match(/^export (\w+)="(.+)"$/)
    if (matched) {
      process.env[matched[1]] = matched[2]
    }
  }
}

export interface LocalKubernetesConfig extends KubernetesConfig {
  _system?: Symbol
  _systemServices?: string[]
}

const configSchema = providerConfigBase
  .keys({
    context: Joi.string()
      .description("The kubectl context to use to connect to the Kubernetes cluster."),
    ingressHostname: Joi.string()
      .description("The hostname of the cluster's ingress controller."),
    _system: Joi.any().meta({ internal: true }),
    _systemServices: Joi.array().items(Joi.string())
      .meta({ internal: true })
      .description("The system services which should be automatically deployed to the cluster."),
  })
  .description("The provider configuration for the local-kubernetes plugin.")

export const name = "local-kubernetes"

export async function gardenPlugin({ config, logEntry }): Promise<GardenPlugin> {
  config = validate(config, configSchema, { context: "kubernetes provider config" })

  let context = config.context
  let systemServices
  let ingressHostname
  let ingressPort

  if (!context) {
    // automatically detect supported kubectl context if not explicitly configured
    const kubeConfig = await getKubeConfig()
    const currentContext = kubeConfig["current-context"]

    if (currentContext && supportedContexts.includes(currentContext)) {
      // prefer current context if set and supported
      context = currentContext
      logEntry.debug({ section: name, msg: `Using current context: ${context}` })
    } else if (kubeConfig.contexts) {
      const availableContexts = kubeConfig.contexts.map(c => c.name)

      for (const supportedContext of supportedContexts) {
        if (availableContexts.includes(supportedContext)) {
          context = supportedContext
          logEntry.debug({ section: name, msg: `Using detected context: ${context}` })
          break
        }
      }
    }
  }

  if (!context) {
    context = supportedContexts[0]
    logEntry.debug({ section: name, msg: `No kubectl context auto-deteced, using default: ${context}` })
  }

  if (context === "minikube") {
    await execa("minikube", ["config", "set", "WantUpdateNotification", "false"])

    ingressHostname = config.ingressHostname

    if (!ingressHostname) {
      // use the nip.io service to give a hostname to the instance, if none is explicitly configured
      const minikubeIp = await execa.stdout("minikube", ["ip"])
      ingressHostname = minikubeIp + ".nip.io"
    }

    await Promise.all([
      execa("minikube", ["addons", "enable", "ingress"]),
      setMinikubeDockerEnv(),
    ])

    ingressPort = 80
    systemServices = []
  } else {
    ingressHostname = config.ingressHostname || "local.app.garden"
    ingressPort = 32000
  }

  const k8sConfig: LocalKubernetesConfig = {
    name: config.name,
    context,
    ingressHostname,
    ingressPort,
    ingressClass: "nginx",
    // TODO: support SSL on local deployments
    forceSsl: false,
    defaultUsername: "default",
    _system: config._system,
    _systemServices: systemServices,
  }

  const plugin = k8sPlugin({ config: k8sConfig })

  plugin.actions!.getEnvironmentStatus = getLocalEnvironmentStatus
  plugin.actions!.configureEnvironment = configureLocalEnvironment

  return plugin
}
