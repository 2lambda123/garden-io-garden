/*
 * Copyright (C) 2018 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { RunResult } from "../../types/plugin/base"
import { kubectl } from "./kubectl"
import { PrimitiveMap } from "../../config/common"
import { Module } from "../../types/module"
import { LogEntry } from "../../logger/log-entry"

interface RunPodParams {
  context: string,
  namespace: string,
  module: Module,
  image: string,
  envVars: PrimitiveMap,
  command?: string[],
  args: string[],
  interactive: boolean,
  ignoreError: boolean,
  timeout?: number,
  overrides?: any,
  log: LogEntry,
}

export async function runPod(
  {
    context, namespace, module, image, envVars,
    command, args, interactive, ignoreError,
    timeout, overrides, log,
  }: RunPodParams,
): Promise<RunResult> {
  const envArgs = Object.entries(envVars).map(([k, v]) => `--env=${k}=${v}`)

  const cmd = (command && command.length) ? command : []

  const opts = [
    `--image=${image}`,
    "--restart=Never",
    "--quiet",
    "--rm",
    // Need to attach to get the log output and exit code.
    "-i",
  ]

  if (overrides) {
    opts.push("--overrides", `${JSON.stringify(overrides)}`)
  }

  if (interactive) {
    opts.push("--tty")
  }

  if (cmd.length) {
    opts.push("--command")
  }

  const kubecmd = [
    "run", `run-${module.name}-${Math.round(new Date().getTime())}`,
    ...opts,
    ...envArgs,
    "--",
    ...cmd,
    ...args,
  ]

  log.verbose(`Running ${cmd.join(" ")} '${args.join(" ")}'`)

  const startedAt = new Date()

  const res = await kubectl.spawnAndWait({
    log,
    context,
    namespace,
    ignoreError,
    args: kubecmd,
    timeout,
    tty: interactive,
  })

  return {
    moduleName: module.name,
    command: [...cmd, ...args],
    version: module.version,
    startedAt,
    completedAt: new Date(),
    output: res.output,
    success: res.code === 0,
  }
}
