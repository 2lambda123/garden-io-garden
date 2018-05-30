/*
 * Copyright (C) 2018 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { NotFoundError } from "../../exceptions"
import { PluginContext } from "../../plugin-context"
import {
  Command,
  CommandResult,
  ParameterValues,
  StringParameter,
} from "../base"
import dedent = require("dedent")

export const configGetArgs = {
  key: new StringParameter({
    help: "The key of the configuration variable. Separate with dots to get a nested key (e.g. key.nested).",
    required: true,
  }),
}

export type GetArgs = ParameterValues<typeof configGetArgs>

// TODO: allow omitting key to return all configs

export class ConfigGetCommand extends Command<typeof configGetArgs> {
  name = "get"
  help = "Get a configuration variable from the environment."

  description = dedent`
    Returns with an error if the provided key could not be found in the configuration.

    Examples:

        garden get somekey
        garden get some.nested.key
  `

  arguments = configGetArgs

  async action(ctx: PluginContext, args: GetArgs): Promise<CommandResult> {
    const key = args.key.split(".")
    const { value } = await ctx.getConfig({ key })

    if (value === null || value === undefined) {
      throw new NotFoundError(`Could not find config key ${args.key}`, { key })
    }

    ctx.log.info(value)

    return { [args.key]: value }
  }
}
