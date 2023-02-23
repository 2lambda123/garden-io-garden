/*
 * Copyright (C) 2018-2022 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { Parameters } from "@garden-io/core/build/src/cli/params"
import { prepareMinimistOpts } from "@garden-io/core/build/src/cli/helpers"
import { isTruthy } from "@garden-io/core/build/src/util/util"
import { flatten, pick, without } from "lodash"
import minimist from "minimist"

export {
  BooleanParameter,
  ChoicesParameter,
  DurationParameter,
  IntegerParameter,
  PathParameter,
  PathsParameter,
  StringOption,
  StringsParameter,
  TagsOption,
} from "@garden-io/core/build/src/cli/params"

/**
 * Parses the given CLI arguments using minimist, according to the CLI options spec provided. Useful for plugin commands
 * that want to support CLI options. Any CLI options not present in `optionSpec` will be returned as `otherOpts`.
 *
 * @param stringArgs  Raw string arguments
 * @param optionSpec  A map of CLI options that should be detected and parsed.
 * @param cli         If true, prefer `option.cliDefault` to `option.defaultValue`.
 * @param skipDefault Defaults to `false`. If `true`, don't populate default values.
 */
export function parsePluginCommandArgs(params: {
  stringArgs: string[]
  optionSpec: Parameters
  cli: boolean
  skipDefault?: boolean
}) {
  const { stringArgs, optionSpec } = params
  const minimistOpts = prepareMinimistOpts({
    options: optionSpec,
    ...params,
  })

  const parsed = minimist(stringArgs, {
    ...minimistOpts,
    "--": true,
  })

  const optionKeysFromSpec = flatten(Object.entries(optionSpec).map(([optName, { alias }]) => [optName, alias])).filter(
    isTruthy
  )

  return {
    args: parsed["_"],
    opts: parsed,
    otherOpts: pick(parsed, ...without(Object.keys(parsed), ...optionKeysFromSpec, "_", "--")),
  }
}

export function unparseMinimistOptions(opts: { [name: string]: string | number | boolean }): string[] {
  return flatten(
    Object.entries(opts).map(([opt, val]) => {
      const renderedOpt = opt.length === 1 ? `-${opt}` : `--${opt}`
      if (typeof val === "boolean") {
        return [renderedOpt]
      } else {
        return [renderedOpt, val.toString()]
      }
    })
  ).filter(isTruthy)
}
