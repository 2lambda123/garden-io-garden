/*
 * Copyright (C) 2018-2022 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import tmp from "tmp-promise"
import { expect } from "chai"
import { createProjectConfig, makeTempDir, TestGarden } from "../../../helpers"
import { ProjectConfig } from "../../../../src/config/project"
import { createGardenPlugin } from "../../../../src/plugin/plugin"
import { RunTask } from "../../../../src/tasks/run"
import { GetRunResult } from "../../../../src/plugin/handlers/Run/get-result"
import { joi } from "../../../../src/config/common"

describe("RunTask", () => {
  let tmpDir: tmp.DirectoryResult
  let config: ProjectConfig

  before(async () => {
    tmpDir = await makeTempDir({ git: true, initialCommit: false })

    config = createProjectConfig({
      path: tmpDir.path,
      providers: [{ name: "test" }],
    })
  })

  after(async () => {
    await tmpDir.cleanup()
  })

  describe("process", () => {
    let cache: { [key: string]: GetRunResult } = {}

    beforeEach(() => {
      cache = {}
    })

    const testPlugin = createGardenPlugin({
      name: "test",
      createActionTypes: {
        Run: [
          {
            name: "test",
            docs: "test",
            schema: joi.object(),
            handlers: {
              run: async (params) => {
                const log = new Date().getTime().toString()

                const result: GetRunResult = {
                  state: "ready",
                  detail: {
                    completedAt: new Date(),
                    log: params.action.getSpec().command.join(" "),
                    startedAt: new Date(),
                    success: true,
                  },
                  outputs: { log },
                }

                cache[params.action.key()] = result

                return result
              },
              getResult: async (params) => {
                return (
                  cache[params.action.key()] || {
                    state: "not-ready",
                    outputs: {},
                  }
                )
              },
            },
          },
        ],
      },
    })

    it("should cache results", async () => {
      const garden = await TestGarden.factory(tmpDir.path, { config, plugins: [testPlugin] })

      garden.setActionConfigs(
        [],
        [
          {
            name: "test",
            type: "test",
            kind: "Run",
            dependencies: [],
            disabled: false,
            timeout: 10,
            internal: {
              basePath: "./",
            },
            spec: {
              command: ["echo", "this is a test lalala kumiko"],
            },
          },
        ]
      )

      let graph = await garden.getConfigGraph({ log: garden.log, emit: false })
      let taskTask = new RunTask({
        garden,
        graph,
        action: graph.getRun("test"),
        force: false,
        forceBuild: false,
        log: garden.log,
        devModeDeployNames: [],
        localModeDeployNames: [],
      })

      let result = await garden.processTasks({ tasks: [taskTask], throwOnError: true })
      const logA = result.results.getAll()[0]?.outputs

      result = await garden.processTasks({ tasks: [taskTask], throwOnError: true })
      const logB = result.results.getAll()[0]?.outputs

      // Expect the same log from the second run
      expect(logA).to.eql(logB)
    })
  })
})
