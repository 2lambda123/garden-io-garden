/*
 * Copyright (C) 2018-2023 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { DeployAction } from "../../../actions/deploy"
import { actionParamsSchema, PluginDeployActionParamsBase } from "../../../plugin/base"
import { dedent } from "../../../util/string"
import { ServiceStatus, serviceStatusSchema } from "../../../types/service"
import { ActionTypeHandlerSpec } from "../base/base"
import type { ActionStatus, Resolved } from "../../../actions/types"
import { createSchema } from "../../../config/common"
import { actionStatusSchema } from "../../../actions/base"

type DeleteDeployParams<T extends DeployAction> = PluginDeployActionParamsBase<T>

type DeleteDeployStatus<T extends DeployAction = DeployAction> = ActionStatus<T, ServiceStatus, {}>

export const getDeleteDeployResultSchema = createSchema({
  name: "delete-deploy-result",
  keys: () => ({
    detail: serviceStatusSchema,
  }),
  extend: actionStatusSchema,
})

export class DeleteDeploy<T extends DeployAction = DeployAction> extends ActionTypeHandlerSpec<
  "Deploy",
  DeleteDeployParams<Resolved<T>>,
  DeleteDeployStatus<T>
> {
  description = dedent`
    Terminate a deployed service. This should wait until the service is no longer running.

    Called by the \`garden delete service\` command.
  `

  paramsSchema = () => actionParamsSchema()
  resultSchema = () => getDeleteDeployResultSchema()
}
