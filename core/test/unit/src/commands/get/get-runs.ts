/*
 * Copyright (C) 2018-2023 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { makeTestGarden, withDefaultGlobalOpts, getDataDir } from "../../../../helpers"
import { GetRunsCommand } from "../../../../../src/commands/get/get-runs"

describe("GetRunsCommand", () => {
  const projectRoot = getDataDir("test-project-b")

  it("should run without errors when called without arguments", async () => {
    const garden = await makeTestGarden(projectRoot)
    const log = garden.log
    const command = new GetRunsCommand()

    await command.action({
      garden,
      log,
      args: { names: undefined },
      opts: withDefaultGlobalOpts({ "detail": false, "sort": "name", "include-state": false }),
    })
  })

  it("should run without errors when called with a list of task names", async () => {
    const garden = await makeTestGarden(projectRoot)
    const log = garden.log
    const command = new GetRunsCommand()

    await command.action({
      garden,
      log,
      args: { names: ["task-a"] },
      opts: withDefaultGlobalOpts({ "detail": false, "sort": "name", "include-state": false }),
    })
  })
})
