/*
 * Copyright (C) 2018-2022 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import chalk from "chalk"
import hasAnsi from "has-ansi"
import { every, some } from "lodash"
import Stream from "ts-stream"
import type { DeployAction } from "../actions/deploy"
import { Resolved } from "../actions/types"
import { ConfigGraph } from "../graph/config-graph"
import { Log } from "../logger/log-entry"
import { LogLevel, logLevelMap } from "../logger/logger"
import { padSection } from "../logger/renderers"
import { PluginEventBroker } from "../plugin-context"
import { waitForOutputFlush } from "../process"
import { DeployLogEntry } from "../types/service"
import { MonitorBaseParams, Monitor } from "./base"

export const logMonitorColors = ["green", "cyan", "magenta", "yellow", "blueBright", "red"]

// Track these globally, across many monitors
let colorMap: { [name: string]: string } = {}
let colorIndex = -1
// If the container name should be displayed, we align the output wrt to the longest container name
let maxDeployName = 1

interface LogMonitorParams extends MonitorBaseParams {
  action: Resolved<DeployAction>
  graph: ConfigGraph
  log: Log
  events?: PluginEventBroker

  collect: boolean
  hideService: boolean
  showTags: boolean
  showTimestamps: boolean
  logLevel: LogLevel
  tagFilters?: LogsTagOrFilter
}

export type LogsTagFilter = [string, string]
export type LogsTagAndFilter = LogsTagFilter[]
export type LogsTagOrFilter = LogsTagAndFilter[]

export class LogMonitor extends Monitor {
  type = "log"

  public action: Resolved<DeployAction>

  private graph: ConfigGraph
  private log: Log

  private entries: DeployLogEntry[]
  private events: PluginEventBroker

  private collect: boolean
  private hideService: boolean
  private showTags: boolean
  private showTimestamps: boolean
  private logLevel: LogLevel
  private tagFilters?: LogsTagOrFilter

  constructor(params: LogMonitorParams) {
    super(params)

    this.action = params.action
    this.graph = params.graph
    this.log = params.log

    this.entries = []
    this.events = params.events || new PluginEventBroker(params.garden)

    this.collect = params.collect
    this.hideService = params.hideService
    this.showTags = params.showTags
    this.showTimestamps = params.showTimestamps
    this.logLevel = params.logLevel
    this.tagFilters = params.tagFilters
  }

  static getColorForName(name: string) {
    if (!colorMap[name]) {
      colorMap[name] = logMonitorColors[++colorIndex % logMonitorColors.length]
    }
    return colorMap[name]
  }

  static resetGlobalState() {
    maxDeployName = 1
    colorMap = {}
    colorIndex = -1
  }

  key() {
    return this.action.key()
  }

  description() {
    return `log monitor for ${this.action.longDescription()}`
  }

  async start() {
    const stream = new Stream<DeployLogEntry>()
    // Note: lazy-loading for startup performance
    const { isMatch } = require("micromatch")

    const matchTagFilters = (entry: DeployLogEntry): boolean => {
      if (!this.tagFilters) {
        return true
      }
      // We OR together the filter results of each tag option instance.
      return some(this.tagFilters, (andFilter: LogsTagAndFilter) => {
        // We AND together the filter results within a given tag option instance.
        return every(andFilter, ([key, value]: LogsTagFilter) => {
          return isMatch(entry.tags?.[key] || "", value)
        })
      })
    }

    void stream.forEach((entry) => {
      // Skip empty entries
      if (skipEntry(entry)) {
        return
      }

      // Match against all of the specified filters, if any
      if (!matchTagFilters(entry)) {
        return
      }

      if (this.collect) {
        this.entries.push(entry)
      } else {
        this.logEntry(entry)
      }
    })

    const router = await this.garden.getActionRouter()
    await router.deploy.getLogs({
      log: this.garden.log,
      action: this.action,
      follow: !this.collect,
      graph: this.graph,
      stream,
      events: this.events,
    })

    if (this.collect) {
      await waitForOutputFlush()
    }

    return {}
  }

  async stop() {
    this.events.emit("abort")
    return {}
  }

  getEntries() {
    return [...this.entries]
  }

  logEntry(entry: DeployLogEntry) {
    const levelStr = logLevelMap[entry.level || LogLevel.info] || "info"
    const msg = this.formatLogMonitorEntry(entry)
    this.command.emit(this.log, JSON.stringify({ msg, timestamp: entry.timestamp?.getTime(), level: levelStr }))
    this.log[levelStr]({ msg })
  }

  private formatLogMonitorEntry(entry: DeployLogEntry) {
    const style = chalk[LogMonitor.getColorForName(entry.name)]
    const sectionStyle = style.bold
    const serviceLog = entry.msg
    const entryLevel = entry.level || LogLevel.info

    let timestamp: string | undefined
    let tags: string | undefined

    if (this.showTimestamps && entry.timestamp) {
      timestamp = "                        "
      try {
        timestamp = entry.timestamp.toISOString()
      } catch {}
    }

    if (this.showTags && entry.tags) {
      tags = Object.entries(entry.tags)
        .map(([k, v]) => `${k}=${v}`)
        .join(" ")
    }

    if (entryLevel <= this.logLevel) {
      maxDeployName = Math.max(maxDeployName, entry.name.length)
    }

    let out = ""
    if (!this.hideService) {
      out += `${sectionStyle(padSection(entry.name, maxDeployName))} → `
    }
    if (timestamp) {
      out += `${chalk.gray(timestamp)} → `
    }
    if (tags) {
      out += chalk.gray("[" + tags + "] ")
    }
    // If the line doesn't have ansi encoding, we color it white to prevent logger from applying styles.
    out += hasAnsi(serviceLog) ? serviceLog : chalk.white(serviceLog)

    return out
  }
}

export function isLogsMonitor(monitor: Monitor): monitor is LogMonitor {
  return monitor.type === "log"
}

/**
 * Skip empty entries.
 */
function skipEntry(entry: DeployLogEntry) {
  const validDate = entry.timestamp && entry.timestamp instanceof Date && !isNaN(entry.timestamp.getTime())
  return !entry.msg && !validDate
}
