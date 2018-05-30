/*
 * Copyright (C) 2018 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { PluginContext } from "../../plugin-context"
import { EnvironmentStatusMap } from "../../types/plugin/outputs"
import {
  BooleanParameter,
  Command,
  CommandResult,
  ParameterValues,
} from "../base"
import dedent = require("dedent")

export const options = {
  force: new BooleanParameter({ help: "Force reconfiguration of environment, ignoring the environment status check." }),
}

export type Opts = ParameterValues<typeof options>

export class EnvironmentConfigureCommand extends Command<any, Opts> {
  name = "configure"
  alias = "config"
  help = "Configures your environment."

  description = dedent`
    Generally, environments are configured automatically as part of other commands that you run.
    However, this command is useful if you want to make sure the environment is ready before running
    another command, or if you need to force a reconfiguration using the --force flag.

    Examples:

        garden env configure
        garden env configure --force
  `

  options = options

  async action(ctx: PluginContext, _args, opts: Opts): Promise<CommandResult<EnvironmentStatusMap>> {
    const { name } = ctx.getEnvironment()
    ctx.log.header({ emoji: "gear", command: `Configuring ${name} environment` })

    const result = await ctx.configureEnvironment({ force: opts.force })

    ctx.log.info("")
    ctx.log.header({ emoji: "heavy_check_mark", command: `Done!` })

    return { result }
  }
}
