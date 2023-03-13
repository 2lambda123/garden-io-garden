/*
 * Copyright (C) 2018-2022 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { memoize } from "lodash"
import { joi } from "../config/common"
import {
  BaseRuntimeActionConfig,
  baseRuntimeActionConfigSchema,
  ExecutedRuntimeAction,
  ResolvedRuntimeAction,
  RuntimeAction,
} from "./base"
import { Action, BaseActionConfig } from "./types"

export interface TestActionConfig<N extends string = any, S extends object = any>
  extends BaseRuntimeActionConfig<"Test", N, S> {
  timeout?: number
}

export const testActionConfigSchema = memoize(() =>
  baseRuntimeActionConfigSchema().keys({
    kind: joi.string().allow("Test").only(),
    timeout: joi.number().integer().description("Set a timeout for the test to complete, in seconds."),
  })
)

export class TestAction<C extends TestActionConfig = any, O extends {} = any> extends RuntimeAction<C, O> {
  kind: "Test"
}

export class ResolvedTestAction<C extends TestActionConfig = any, O extends {} = any> extends ResolvedRuntimeAction<
  C,
  O
> {
  kind: "Test"
}

export class ExecutedTestAction<C extends TestActionConfig = any, O extends {} = any> extends ExecutedRuntimeAction<
  C,
  O
> {
  kind: "Test"
}

export function isTestAction(action: Action): action is TestAction {
  return action.kind === "Test"
}

export function isTestActionConfig(config: BaseActionConfig): config is TestActionConfig {
  return config.kind === "Test"
}
