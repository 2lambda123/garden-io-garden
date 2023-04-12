/*
 * Copyright (C) 2018-2023 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { PluginRunActionParamsBase, actionParamsSchema, RunResult, runResultSchema } from "../../base"
import { dedent } from "../../../util/string"
import { RunAction } from "../../../actions/run"
import { ActionTypeHandlerSpec } from "../base/base"
import { actionStatusSchema } from "../../../actions/base"
import { ActionStatus, ActionStatusMap, Resolved } from "../../../actions/types"
import { createSchema } from "../../../config/common"

interface GetRunResultParams<T extends RunAction> extends PluginRunActionParamsBase<T> {}

export interface GetRunResult<T extends RunAction = RunAction> extends ActionStatus<T, RunResult> {}

export interface RunStatusMap extends ActionStatusMap<RunAction> {
  [key: string]: GetRunResult
}

export const getRunResultSchema = createSchema({
  name: "get-run-result",
  keys: {
    detail: runResultSchema().allow(null),
  },
  extend: actionStatusSchema,
})

export class GetRunActionResult<T extends RunAction> extends ActionTypeHandlerSpec<
  "Run",
  GetRunResultParams<Resolved<T>>,
  GetRunResult<T>
> {
  description = dedent`
    Retrieve the Run result for the specified version.
  `

  paramsSchema = () => actionParamsSchema()
  resultSchema = () => getRunResultSchema()
}
