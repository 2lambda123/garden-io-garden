/*
 * Copyright (C) 2018 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import * as Bluebird from "bluebird"
import { get, flatten, uniqBy } from "lodash"
import { ChildProcess } from "child_process"
import { V1Pod } from "@kubernetes/client-node"
import getPort = require("get-port")

import { KubernetesResource } from "./types"
import { splitLast } from "../../util/util"
import { KubeApi } from "./api"
import { PluginContext } from "../../plugin-context"
import { LogEntry } from "../../logger/log-entry"
import { KubernetesPluginContext } from "./config"
import { kubectl } from "./kubectl"
import { registerCleanupFunction } from "../../util/util"

export const workloadTypes = ["Deployment", "DaemonSet", "ReplicaSet", "StatefulSet"]

export function getAnnotation(obj: KubernetesResource, key: string): string | null {
  return get(obj, ["metadata", "annotations", key])
}

/**
 * Given a list of resources, get all the associated pods.
 */
export async function getAllPods(api: KubeApi, namespace: string, resources: KubernetesResource[]): Promise<V1Pod[]> {
  const pods = flatten(await Bluebird.map(resources, async (resource) => {
    if (resource.apiVersion === "v1" && resource.kind === "Pod") {
      return [<V1Pod>resource]
    }

    if (isWorkload(resource)) {
      return getWorkloadPods(api, namespace, resource)
    }

    return []
  }))

  return <V1Pod[]>deduplicateResources(pods)
}

/**
 * Given a list of resources, get the names of all the associated pod.
 */
export async function getAllPodNames(api: KubeApi, namespace: string, resources: KubernetesResource[]) {
  return (await getAllPods(api, namespace, resources)).map(p => p.metadata.name)
}

/**
 * Retrieve a list of pods based on the provided label selector.
 */
export async function getWorkloadPods(api: KubeApi, namespace: string, resource: KubernetesResource): Promise<V1Pod[]> {
  const selector = resource.spec.selector.matchLabels
  return getPods(api, resource.metadata.namespace || namespace, selector)
}

/**
 * Retrieve a list of pods based on the provided label selector.
 */
export async function getPods(api: KubeApi, namespace: string, selector: { [key: string]: string }): Promise<V1Pod[]> {
  const selectorString = Object.entries(selector).map(([k, v]) => `${k}=${v}`).join(",")
  const res = await api.core.listNamespacedPod(
    namespace, true, undefined, undefined, undefined, selectorString,
  )
  return res.body.items
}

/**
 * Returns the API group of the resource. Returns empty string for "v1" objects.
 */
export function getApiGroup(resource: KubernetesResource) {
  const split = splitLast(resource.apiVersion, "/")
  return split.length === 1 ? "" : split[0]
}

/**
 * Returns true if the resource is a built-in Kubernetes workload type.
 */
export function isWorkload(resource: KubernetesResource) {
  return isBuiltIn(resource) && workloadTypes.includes(resource.kind)
}

/**
 * Returns true if the resource is a built-in Kubernetes type (e.g. v1, apps/*, *.k8s.io/*)
 */
export function isBuiltIn(resource: KubernetesResource) {
  const apiGroup = getApiGroup(resource)
  return apiGroup.endsWith("k8s.io") || !apiGroup.includes(".")
}

export function deduplicateResources(resources: KubernetesResource[]) {
  return uniqBy(resources, r => `${r.apiVersion}/${r.kind}`)
}

export interface PortForward {
  localPort: number
  proc: ChildProcess
}

const registeredPortForwards: { [key: string]: PortForward } = {}

registerCleanupFunction("kill-port-forward-procs", () => {
  for (const { proc } of Object.values(registeredPortForwards)) {
    !proc.killed && proc.kill()
  }
})

export async function getPortForward(
  ctx: PluginContext, log: LogEntry, namespace: string, targetDeployment: string, port: number,
): Promise<PortForward> {
  let localPort: number

  const key = `${targetDeployment}:${port}`
  const registered = registeredPortForwards[key]

  if (registered && !registered.proc.killed) {
    log.debug(`Reusing local port ${registered.localPort} for ${targetDeployment} container`)
    return registered
  }

  const k8sCtx = <KubernetesPluginContext>ctx

  // Forward random free local port to the remote rsync container.
  localPort = await getPort()
  const portMapping = `${localPort}:${port}`

  log.debug(`Forwarding local port ${localPort} to ${targetDeployment} container port ${port}`)

  // TODO: use the API directly instead of kubectl (need to reverse engineer kubectl a bit to get how that works)
  const portForwardArgs = ["port-forward", targetDeployment, portMapping]
  log.silly(`Running 'kubectl ${portForwardArgs.join(" ")}'`)

  const proc = await kubectl.spawn({ log, context: k8sCtx.provider.config.context, namespace, args: portForwardArgs })

  return new Promise((resolve) => {
    proc.on("error", (error) => {
      !proc.killed && proc.kill()
      throw error
    })

    proc.stdout!.on("data", (line) => {
      // This is unfortunately the best indication that we have that the connection is up...
      log.silly(`[${targetDeployment} port forwarder] ${line}`)

      if (line.toString().includes("Forwarding from ")) {
        const portForward = { proc, localPort }
        registeredPortForwards[key] = portForward
        resolve(portForward)
      }
    })
  })
}

/**
 * Converts the given number of millicpus (1000 mcpu = 1 CPU) to a string suitable for use in pod resource limit specs.
 */
export function millicpuToString(mcpu: number) {
  mcpu = Math.floor(mcpu)

  if (mcpu % 1000 === 0) {
    return (mcpu / 1000).toString(10)
  } else {
    return `${mcpu}m`
  }
}

/**
 * Converts the given number of kilobytes to a string suitable for use in pod/volume resource specs.
 */
export function kilobytesToString(kb: number) {
  kb = Math.floor(kb)

  for (const [suffix, power] of Object.entries(suffixTable)) {
    if (kb % (1024 ** power) === 0) {
      return `${(kb / (1024 ** power))}${suffix}`
    }
  }

  return `${kb}Ki`
}

/**
 * Converts the given number of megabytes to a string suitable for use in pod/volume resource specs.
 */
export function megabytesToString(mb: number) {
  return kilobytesToString(mb * 1024)
}

const suffixTable = {
  Ei: 5,
  Pi: 4,
  Ti: 3,
  Gi: 2,
  Mi: 1,
}
