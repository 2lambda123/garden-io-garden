/*
 * Copyright (C) 2018 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { PluginContext } from "../../plugin-context"
import { SetConfigResult } from "../../types/plugin/outputs"
import {
  Command,
  CommandResult,
  ParameterValues,
  StringParameter,
} from "../base"

export const configSetArgs = {
  // TODO: specify and validate config key schema here
  key: new StringParameter({
    help: "The key of the configuration variable. Separate with dots to set a nested key (e.g. key.nested)",
    required: true,
  }),
  value: new StringParameter({
    help: "The value of the configuration variable",
    required: true,
  }),
}

export type SetArgs = ParameterValues<typeof configSetArgs>

// TODO: allow reading key/value pairs from a file

export class ConfigSetCommand extends Command<typeof configSetArgs> {
  name = "set"
  help = "Set a configuration variable"

  arguments = configSetArgs

  async action(ctx: PluginContext, args: SetArgs): Promise<CommandResult<SetConfigResult>> {
    const key = args.key.split(".")
    const result = await ctx.setConfig({ key, value: args.value })
    ctx.log.info(`Set config key ${args.key}`)
    return { result }
  }
}
