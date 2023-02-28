/*
 * Copyright (C) 2018-2022 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { omit } from "lodash"
import { EventEmitter2 } from "eventemitter2"
import type { LogEntryEventPayload } from "./cloud/buffered-event-stream"
import type { ServiceStatus } from "./types/service"
import type { RunStatus } from "./plugin/base"
import type { Omit } from "./util/util"
import type { AuthTokenResponse } from "./cloud/api"
import type { RenderedActionGraph } from "./graph/config-graph"
import type { CommandInfo } from "./plugin-context"
import type { BuildState } from "./plugin/handlers/Build/get-status"
import type { ActionReference } from "./config/common"
import type { GraphResult } from "./graph/results"
import { NamespaceStatus } from "./types/namespace"
import { sanitizeValue } from "./logger/logger"

export type GardenEventListener<T extends EventName> = (payload: Events[T]) => void

/**
 * This simple class serves as the central event bus for a Garden instance. Its function
 * is mainly to consolidate all events for the instance, to ensure type-safety.
 *
 * See below for the event interfaces.
 */
export class EventBus extends EventEmitter2 {
  constructor() {
    super({
      wildcard: false,
      newListener: false,
      maxListeners: 100, // we may need to adjust this
    })
  }

  emit<T extends EventName>(name: T, payload: Events[T]) {
    return super.emit(name, payload)
  }

  on<T extends EventName>(name: T, listener: (payload: Events[T]) => void) {
    return super.on(name, listener)
  }

  onAny(listener: <T extends EventName>(name: T, payload: Events[T]) => void) {
    return super.onAny(<any>listener)
  }

  once<T extends EventName>(name: T, listener: (payload: Events[T]) => void) {
    return super.once(name, listener)
  }

  // TODO: wrap more methods to make them type-safe
}

/**
 * Supported logger events and their interfaces.
 */
export interface LoggerEvents {
  _test: any
  logEntry: LogEntryEventPayload
}

export type LoggerEventName = keyof LoggerEvents

export type GraphResultEventPayload = Omit<GraphResult, "task" | "dependencyResults" | "error"> & {
  error: string | null
}

export interface ServiceStatusPayload extends Omit<ServiceStatus, "detail"> {
  /**
   * ISO format date string
   */
  deployStartedAt?: string
  /**
   * ISO format date string
   */
  deployCompletedAt?: string
}

export interface CommandInfoPayload extends CommandInfo {
  // Contains additional context for the command info available during init
  environmentName: string
  environmentId: number | undefined
  projectName: string
  projectId: string
  namespaceName: string
  namespaceId: number | undefined
  coreVersion: string
  vcsBranch: string
  vcsCommitHash: string
  vcsOriginUrl: string
}

export function toGraphResultEventPayload(result: GraphResult): GraphResultEventPayload {
  const payload = sanitizeValue({
    ...omit(result, "dependencyResults", "task"),
    error: result.error ? String(result.error) : null,
  })
  if (payload.result) {
    // TODO: Use a combined blacklist of fields from all task types instead of hardcoding here.
    payload.result = omit(
      result.result,
      "dependencyResults",
      "log",
      "buildLog",
      "detail",
      "resolvedAction",
      "executedAction"
    )
  }
  return payload
}

/**
 * Supported Garden events and their interfaces.
 */
export interface Events extends LoggerEvents {
  // Internal test/control events
  _exit: {}
  _restart: {}
  _test: any
  _workflowRunRegistered: {
    workflowRunUid: string
  }

  // Process events
  serversUpdated: {
    servers: { host: string; command: string; serverAuthKey: string }[]
  }
  serverReady: {}
  receivedToken: AuthTokenResponse

  // Session events - one of these is emitted when the command process ends
  sessionCompleted: {} // Command exited with a 0 status
  sessionFailed: {} // Command exited with a nonzero status
  sessionCancelled: {} // Command exited because of an interrupt signal (e.g. CTRL-C)

  // Watcher events
  configAdded: {
    path: string
  }
  configRemoved: {
    path: string
  }
  internalError: {
    timestamp: Date
    error: Error
  }
  projectConfigChanged: {}
  actionConfigChanged: {
    names: string[]
    path: string
  }
  actionSourcesChanged: {
    refs: ActionReference[]
    pathsChanged: string[]
  }
  actionRemoved: {}

  // Command/project metadata events
  commandInfo: CommandInfoPayload

  // Stack Graph events
  stackGraph: RenderedActionGraph

  // TaskGraph events
  taskPending: {
    /**
     * ISO format date string
     */
    addedAt: string
    key: string
    type: string
    name: string
  }
  taskProcessing: {
    /**
     * ISO format date string
     */
    startedAt: string
    key: string
    type: string
    name: string
    inputVersion: string
  }
  taskComplete: GraphResultEventPayload
  taskError: GraphResultEventPayload
  taskCancelled: {
    /**
     * ISO format date string
     */
    cancelledAt: string
    type: string
    key: string
    name: string
  }
  taskGraphProcessing: {
    /**
     * ISO format date string
     */
    startedAt: string
  }
  taskGraphComplete: {
    /**
     * ISO format date string
     */
    completedAt: string
  }
  watchingForChanges: {}
  log: {
    /**
     * ISO format date string
     */
    timestamp: string
    actionUid: string
    entity: {
      moduleName: string | null
      type: string
      key: string
    }
    data: string
  }

  // Status events

  /**
   * In the `buildStatus`, `taskStatus`, `testStatus` and `serviceStatus` events, the optional `actionUid` field
   * identifies a single build/deploy/run.
   *
   * The `build`/`testModule`/`runTask`/`deployService` actions emit two events: One before the plugin handler is
   * called (a "building"/"running"/"deploying" event), and another one after the handler finishes successfully or
   * throws an error.
   *
   * When logged in, the `actionUid` is used by the Garden Cloud backend to group these two events for each of these
   * action invocations.
   *
   * No `actionUid` is set for the corresponding "get status" actions (e.g. `getBuildStatus` or `getServiceStatus`),
   * since those actions don't result in a build/deploy/run (so there are no associated logs or timestamps to track).
   */

  buildStatus: {
    actionName: string
    actionVersion: string

    // DEPRECATED: remove in 0.14
    moduleName: string | null
    moduleVersion: string
    /**
     * `actionUid` should only be defined if `state = "building" | "built" | "failed"` (and not if `state = "fetched",
     * since in that case, no build took place and there are no logs/timestamps to view).
     */
    actionUid?: string
    status: {
      state: BuildState
      /**
       * ISO format date string
       */
      startedAt?: string
      /**
       * ISO format date string
       */
      completedAt?: string
    }
  }
  taskStatus: {
    actionName: string
    actionVersion: string

    // DEPRECATED: remove in 0.14
    taskName: string
    moduleName: string | null
    moduleVersion: string
    taskVersion: string
    /**
     * `actionUid` should only be defined if the task was run , i.e. if `state = "running" | "succeeded" | "failed"`
     * (and not if `state = "outdated" | "not-implemented, since in that case, no run took place and there are no
     * logs/timestamps to view).
     */
    actionUid?: string
    status: RunStatus
  }
  testStatus: {
    actionName: string
    actionVersion: string

    // DEPRECATED: remove in 0.14
    testName: string
    moduleName: string | null
    moduleVersion: string
    testVersion: string
    /**
     * `actionUid` should only be defined if the test was run, i.e. if `state = "running" | "succeeded" | "failed"`
     * (and not if `state = "outdated" | "not-implemented, since in that case, no run took place and there are no
     * logs/timestamps to view).
     */
    actionUid?: string
    status: RunStatus
  }
  serviceStatus: {
    actionName: string
    actionVersion: string

    // DEPRECATED: remove in 0.14
    serviceName: string
    moduleName: string | null
    moduleVersion: string
    serviceVersion: string
    /**
     * `actionUid` should only be defined if a deploy took place (i.e. when emitted from the `deployService` action).
     */
    actionUid?: string
    status: ServiceStatusPayload
  }
  namespaceStatus: NamespaceStatus

  // Workflow events
  workflowRunning: {}
  workflowComplete: {}
  workflowError: {}
  workflowStepProcessing: {
    index: number
  }
  workflowStepSkipped: {
    index: number
  }
  workflowStepComplete: {
    index: number
    durationMsec: number
  }
  workflowStepError: {
    index: number
    durationMsec: number
  }
}

export type EventName = keyof Events

/**
 * These events indicate a request from Cloud to Core.
 */

// Note: Does not include logger events.
export const pipedEventNames: EventName[] = [
  "_exit",
  "_restart",
  "_test",
  "_workflowRunRegistered",
  "sessionCompleted",
  "sessionFailed",
  "sessionCancelled",
  "configAdded",
  "configRemoved",
  "internalError",
  "log",
  "actionConfigChanged",
  "actionRemoved",
  "commandInfo",
  "actionSourcesChanged",
  "namespaceStatus",
  "projectConfigChanged",
  "serviceStatus",
  "stackGraph",
  "taskCancelled",
  "taskComplete",
  "taskError",
  "taskGraphComplete",
  "taskGraphProcessing",
  "taskPending",
  "taskProcessing",
  "buildStatus",
  "taskStatus",
  "testStatus",
  "watchingForChanges",
  "workflowComplete",
  "workflowError",
  "workflowRunning",
  "workflowStepComplete",
  "workflowStepError",
  "workflowStepProcessing",
  "workflowStepSkipped",
]
