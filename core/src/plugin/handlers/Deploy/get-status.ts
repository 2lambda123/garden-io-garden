/*
 * Copyright (C) 2018-2022 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { actionParamsSchema, PluginDeployActionParamsBase } from "../../base"
import { dedent } from "../../../util/string"
import { ServiceStatus, serviceStatusSchema } from "../../../types/service"
import { createSchema } from "../../../config/common"
import type { DeployAction } from "../../../actions/deploy"
import { ActionTypeHandlerSpec } from "../base/base"
import type { ActionStatus, ActionStatusMap, GetActionOutputType, Resolved } from "../../../actions/types"
import { actionStatusSchema } from "../../../actions/base"

interface GetDeployStatusParams<T extends DeployAction> extends PluginDeployActionParamsBase<T> {}

export type DeployStatus<T extends DeployAction = DeployAction> = ActionStatus<
  T,
  ServiceStatus<any, GetActionOutputType<T>>
>

export interface DeployStatusMap extends ActionStatusMap<DeployAction> {
  [key: string]: DeployStatus
}

export const getDeployStatusSchema = createSchema({
  name: "get-deploy-status",
  keys: {
    detail: serviceStatusSchema,
  },
  extend: actionStatusSchema,
})

export class GetDeployStatus<T extends DeployAction = DeployAction> extends ActionTypeHandlerSpec<
  "Deploy",
  GetDeployStatusParams<Resolved<T>>,
  DeployStatus<T>
> {
  description = dedent`
    Check and return the current runtime status of a deployment.

    Called ahead of any actions that expect a deployment to be running, as well as the \`garden get status\` command.
  `

  paramsSchema = () => actionParamsSchema()
  resultSchema = () => getDeployStatusSchema()
}
