/*
 * Copyright (C) 2018-2022 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import tmp from "tmp-promise"
import execa from "execa"

import { ProjectConfig } from "../../../../src/config/project"
import { ConfigGraph } from "../../../../src/graph/config-graph"
import { createGardenPlugin, GardenPlugin } from "../../../../src/plugin/plugin"
import { DeployTask } from "../../../../src/tasks/deploy"
import { expect } from "chai"
import { createProjectConfig, makeTempDir, TestGarden } from "../../../helpers"
import { joi } from "../../../../src/config/common"

describe("DeployTask", () => {
  let tmpDir: tmp.DirectoryResult
  let garden: TestGarden
  let graph: ConfigGraph
  let config: ProjectConfig
  let testPlugin: GardenPlugin

  before(async () => {
    tmpDir = await makeTempDir({ git: true, initialCommit: false })

    config = createProjectConfig({
      path: tmpDir.path,
      providers: [{ name: "test" }],
    })

    testPlugin = createGardenPlugin({
      name: "test",
      docs: "asd",
      createActionTypes: {
        Build: [
          {
            name: "test",
            docs: "asd",
            schema: joi.object(),
            handlers: {
              build: async (_) => ({ state: "ready", detail: {}, outputs: {} }),
            },
          },
        ],
        Deploy: [
          {
            name: "test",
            docs: "asd",
            schema: joi.object(),
            handlers: {
              deploy: async (params) => ({
                state: "ready",
                detail: { detail: {}, state: "ready" },
                outputs: { log: params.action.getSpec().log },
              }),
              getStatus: async (params) => ({
                state: "ready",
                detail: { detail: {}, state: "ready" },
                outputs: { log: params.action.getSpec().log },
              }),
            },
          },
        ],
        Run: [
          {
            name: "test",
            docs: "asdü",
            schema: joi.object(),
            handlers: {
              run: async (params) => ({
                detail: {
                  completedAt: new Date(),
                  log: params.action.getSpec().log,
                  startedAt: new Date(),
                  success: true,
                },
                outputs: {},
                state: "ready",
              }),
            },
          },
        ],
      },
    })
    garden = await TestGarden.factory(tmpDir.path, { config, plugins: [testPlugin] })

    garden.setActionConfigs([
      {
        name: "test-deploy",
        type: "test",
        kind: "Deploy",
        internal: {
          basePath: "foo",
        },
        dependencies: ["deploy.dep-deploy", "run.test-run"],
        disabled: false,

        spec: {
          log: "${runtime.tasks.test-run.outputs.log}",
        },
      },
      {
        name: "dep-deploy",
        type: "test",
        kind: "Deploy",
        internal: {
          basePath: "foo",
        },
        dependencies: [],
        disabled: false,
        spec: {
          log: "apples and pears",
        },
      },
      {
        name: "test-run",
        type: "test",
        kind: "Run",
        dependencies: [],
        disabled: false,
        timeout: 10,
        internal: {
          basePath: "./",
        },
        spec: {
          log: "test output",
        },
      },
    ])

    graph = await garden.getConfigGraph({ log: garden.log, emit: false })
  })

  after(async () => {
    await tmpDir.cleanup()
  })

  describe("resolveProcessDependencies", () => {
    it("should always return deploy action's dependencies having force = false", async () => {
      const action = graph.getDeploy("test-deploy")

      const forcedDeployTask = new DeployTask({
        garden,
        graph,
        action,
        force: true,
        forceBuild: false,

        log: garden.log,
        devModeDeployNames: [],
        localModeDeployNames: [],
      })

      expect(forcedDeployTask.resolveProcessDependencies({ status: null }).find((dep) => dep.type === "run")!.force).to
        .be.false

      const unforcedDeployTask = new DeployTask({
        garden,
        graph,
        action,
        force: false,
        forceBuild: false,

        log: garden.log,
        devModeDeployNames: [],
        localModeDeployNames: [],
      })

      expect(unforcedDeployTask.resolveProcessDependencies({ status: null }).find((dep) => dep.type === "run")!.force)
        .to.be.false
    })

    it("returns just the resolve task if the status is ready", async () => {
      throw "TODO"
    })

    context("when skipRuntimeDependencies = true", () => {
      it("doesn't return deploy or run dependencies", async () => {
        const action = graph.getDeploy("test-deploy")

        const deployTask = new DeployTask({
          garden,
          graph,
          action,
          force: true,
          forceBuild: false,

          log: garden.log,
          skipRuntimeDependencies: true, // <-----
          devModeDeployNames: [],
          localModeDeployNames: [],
        })

        const deps = deployTask.resolveProcessDependencies({ status: null })
        expect(deps.find((dep) => dep.type === "deploy" || dep.type === "run")).to.be.undefined
      })
    })
  })

  describe("process", () => {
    it("should correctly resolve runtime outputs from deploys", async () => {
      const action = graph.getDeploy("test-deploy")

      const deployTask = new DeployTask({
        garden,
        graph,
        action,
        force: true,

        log: garden.log,
        devModeDeployNames: [],
        localModeDeployNames: [],
      })

      const result = await garden.processTasks({ tasks: [deployTask], throwOnError: true })

      expect(result[deployTask.getBaseKey()]!.result.outputs).to.eql({ log: "test output" })
    })
  })
})
