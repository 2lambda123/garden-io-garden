/*
 * Copyright (C) 2018 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { join } from "path"
import { every, values, find } from "lodash"
import { V1Namespace } from "@kubernetes/client-node"
import * as semver from "semver"

import { STATIC_DIR } from "../../constants"
import { Garden } from "../../garden"
import { KubernetesProvider, KubernetesPluginContext } from "./config"
import { LogEntry } from "../../logger/log-entry"
import { KubeApi } from "./api"
import { createNamespace } from "./namespace"
import { getPackageVersion } from "../../util/util"
import { deline } from "../../util/string"
import { deleteNamespaces } from "./namespace"
import { PluginError } from "../../exceptions"
import { DashboardPage } from "../../config/dashboard"
import { PrimitiveMap } from "../../config/common"

const GARDEN_VERSION = getPackageVersion()
const SYSTEM_NAMESPACE_MIN_VERSION = "0.9.0"

const systemProjectPath = join(STATIC_DIR, "kubernetes", "system")
export const systemSymbol = Symbol()
export const systemNamespace = "garden-system"
export const systemMetadataNamespace = "garden-system--metadata"

export function isSystemGarden(provider: KubernetesProvider): boolean {
  return provider.config._system === systemSymbol
}

export async function getSystemGarden(provider: KubernetesProvider, variables: PrimitiveMap): Promise<Garden> {
  return Garden.factory(systemProjectPath, {
    environmentName: "default",
    config: {
      dirname: "system",
      path: systemProjectPath,
      project: {
        apiVersion: "garden.io/v0",
        name: systemNamespace,
        environmentDefaults: {
          providers: [],
          variables: {},
        },
        defaultEnvironment: "default",
        environments: [
          {
            name: "default",
            providers: [
              {
                name: provider.name,
                ...provider.config,
                // Note: this means we can't build images as part of system services
                deploymentRegistry: undefined,
                namespace: systemNamespace,
                _system: systemSymbol,
                _systemServices: [],
              },
            ],
            variables,
          },
        ],
      },
    },
  })
}

/**
 * Returns true if the namespace exists and has an up-to-date version.
 */
export async function systemNamespaceUpToDate(
  api: KubeApi, log: LogEntry, namespace: string, contextForLog: string,
): Promise<boolean> {
  let namespaceResource: V1Namespace

  try {
    namespaceResource = (await api.core.readNamespace(namespace)).body
  } catch (err) {
    if (err.code === 404) {
      return false
    } else {
      throw err
    }
  }

  const versionInCluster = namespaceResource.metadata.annotations["garden.io/version"]

  const upToDate = !!versionInCluster && semver.gte(semver.coerce(versionInCluster)!, SYSTEM_NAMESPACE_MIN_VERSION)

  log.debug(deline`
    ${contextForLog}: current version ${GARDEN_VERSION}, version in cluster: ${versionInCluster},
    oldest permitted version: ${SYSTEM_NAMESPACE_MIN_VERSION}, up to date: ${upToDate}
  `)

  return upToDate
}

/**
 * Returns true if the namespace was outdated.
 */
export async function recreateSystemNamespaces(api: KubeApi, log: LogEntry, namespace: string) {
  const entry = log.debug({
    section: "cleanup",
    msg: "Deleting outdated system namespaces...",
    status: "active",
  })

  const metadataNamespace = `${namespace}--metadata`

  await deleteNamespaces([namespace, metadataNamespace], api, log)

  entry.setState({ msg: "Creating system namespaces..." })
  await createNamespace(api, namespace)
  await createNamespace(api, metadataNamespace)

  entry.setState({ msg: "System namespaces up to date" })
  entry.setSuccess()
}

interface GetSystemServicesStatusParams {
  ctx: KubernetesPluginContext,
  log: LogEntry,
  namespace: string,
  serviceNames: string[],
  variables: PrimitiveMap,
}

export async function getSystemServiceStatuses(
  { ctx, log, namespace, serviceNames, variables }: GetSystemServicesStatusParams,
) {
  let dashboardPages: DashboardPage[] = []

  const sysGarden = await getSystemGarden(ctx.provider, variables)

  const serviceStatuses = await sysGarden.actions.getServiceStatuses({ log, serviceNames })
  const ready = every(values(serviceStatuses).map(s => s.state === "ready"))

  // Add the Kubernetes dashboard to the Garden dashboard
  if (serviceNames.includes("kubernetes-dashboard")) {
    const defaultHostname = ctx.provider.config.defaultHostname

    const dashboardStatus = serviceStatuses["kubernetes-dashboard"]
    const dashboardServiceResource = find(
      (dashboardStatus.detail || {}).remoteObjects || [],
      o => o.kind === "Service",
    )

    if (!!dashboardServiceResource) {
      const dashboardPort = dashboardServiceResource.spec.ports[0].nodePort

      if (!!dashboardPort) {
        dashboardPages.push({
          title: "Kubernetes",
          description: "The standard Kubernetes dashboard for this project",
          url: `http://${defaultHostname}:${dashboardPort}/#!/workload?namespace=${namespace}`,
          newWindow: true,
        })
      }
    }
  }

  return {
    ready,
    dashboardPages,
  }
}

interface PrepareSystemServicesParams extends GetSystemServicesStatusParams {
  force: boolean
}

export async function prepareSystemServices(
  { ctx, log, namespace, serviceNames, force, variables }: PrepareSystemServicesParams,
) {
  const api = await KubeApi.factory(log, ctx.provider.config.context)

  const contextForLog = `Preparing environment for plugin "${ctx.provider.name}"`
  const outdated = !(await systemNamespaceUpToDate(api, log, namespace, contextForLog))

  if (outdated) {
    await recreateSystemNamespaces(api, log, namespace)
  }

  const k8sCtx = <KubernetesPluginContext>ctx
  const provider = k8sCtx.provider
  const sysGarden = await getSystemGarden(provider, variables)

  // Deploy enabled system services
  if (serviceNames.length > 0) {
    const results = await sysGarden.actions.deployServices({
      log,
      serviceNames,
      force,
    })

    const failed = values(results.taskResults).filter(r => !!r.error).length

    if (failed) {
      throw new PluginError(`${provider.name}: ${failed} errors occurred when configuring environment`, {
        results,
      })
    }
  }
}
