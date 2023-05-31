/*
 * Copyright (C) 2018-2023 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { CommandGroup } from "../base"
import { GetGraphCommand } from "./get-graph"
import { GetConfigCommand } from "./get-config"
import { GetEysiCommand } from "./get-eysi"
import { GetStatusCommand } from "./get-status"
import { GetRunsCommand } from "./get-runs"
import { GetRunResultCommand } from "./get-run-result"
import { GetTestResultCommand } from "./get-test-result"
import { GetDebugInfoCommand } from "./get-debug-info"
import { GetLinkedReposCommand } from "./get-linked-repos"
import { GetOutputsCommand } from "./get-outputs"
import { GetDoddiCommand } from "./get-doddi"
import { GetModulesCommand } from "./get-modules"
import { GetTestsCommand } from "./get-tests"
import { GetWorkflowsCommand } from "./get-workflows"
import { GetActionsCommand } from "./get-actions"

export class GetCommand extends CommandGroup {
  name = "get"
  help = "Retrieve and output data and objects, e.g. secrets, status info etc."

  subCommands = [
    GetGraphCommand,
    GetConfigCommand,
    GetDoddiCommand,
    GetEysiCommand,
    GetLinkedReposCommand,
    GetOutputsCommand,
    GetModulesCommand,
    GetStatusCommand,
    GetRunsCommand,
    GetTestsCommand,
    GetRunResultCommand,
    GetTestResultCommand,
    GetDebugInfoCommand,
    GetWorkflowsCommand,
    GetActionsCommand,
  ]
}
