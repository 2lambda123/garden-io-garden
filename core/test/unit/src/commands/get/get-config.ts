/*
 * Copyright (C) 2018-2022 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { expect } from "chai"
import { pick } from "lodash"
import { getDataDir, makeTestGarden, makeTestGardenA, withDefaultGlobalOpts } from "../../../../helpers"
import { GetConfigCommand } from "../../../../../src/commands/get/get-config"
import { sortBy } from "lodash"
import { DEFAULT_API_VERSION } from "../../../../../src/constants"
import { defaultWorkflowResources, WorkflowConfig } from "../../../../../src/config/workflow"
import { defaultContainerLimits } from "../../../../../src/plugins/container/moduleConfig"

describe("GetConfigCommand", () => {
  const command = new GetConfigCommand()

  it("returns all action configs", async () => {
    const garden = await makeTestGardenA()

    const { result } = await garden.runCommand({
      command,
      args: {},
      opts: { "exclude-disabled": false, "resolve": "full" },
    })

    const graph = await garden.getConfigGraph({ log: garden.log, emit: false })
    const actions = graph.getActions()

    for (const action of actions) {
      const config = action.getConfig()
      expect(result!.actionConfigs[action.kind][action.name]).to.eql(config)
    }
  })

  it("should get the project configuration", async () => {
    const garden = await makeTestGardenA()
    const log = garden.log

    const res = await command.action({
      garden,
      log,
      headerLog: log,
      footerLog: log,
      args: {},
      opts: withDefaultGlobalOpts({ "exclude-disabled": false, "resolve": "full" }),
    })

    expect(command.outputsSchema().validate(res.result).error).to.be.undefined

    const expectedModuleConfigs = sortBy(await garden.resolveModules({ log }), "name").map((m) => m._config)

    expect(res.result?.moduleConfigs).to.deep.equal(expectedModuleConfigs)
  })

  it("should include the project name, id, domain and all environment names", async () => {
    const root = getDataDir("test-projects", "login", "has-domain-and-id")
    const garden = await makeTestGarden(root)
    const log = garden.log

    const result = (
      await command.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: {},
        opts: withDefaultGlobalOpts({ "exclude-disabled": false, "resolve": "full" }),
      })
    ).result

    expect(pick(result, ["domain", "projectName", "projectId", "allEnvironmentNames"])).to.eql({
      projectName: "has-domain-and-id",
      projectId: "dummy-id",
      domain: "http://example.invalid",
      allEnvironmentNames: ["local", "other"],
    })
  })

  it("should include workflow configs", async () => {
    const garden = await makeTestGardenA()
    const log = garden.log

    const workflowConfigs: WorkflowConfig[] = [
      {
        apiVersion: DEFAULT_API_VERSION,
        name: "workflow-a",
        kind: "Workflow",
        keepAliveHours: 48,
        limits: defaultContainerLimits,
        path: garden.projectRoot,
        envVars: {},
        resources: defaultWorkflowResources,
        steps: [{ command: ["run", "foo"] }],
      },
    ]
    garden.setWorkflowConfigs(workflowConfigs)

    const res = await command.action({
      garden,
      log,
      headerLog: log,
      footerLog: log,
      args: {},
      opts: withDefaultGlobalOpts({ "exclude-disabled": false, "resolve": "full" }),
    })

    const expectedModuleConfigs = sortBy(await garden.resolveModules({ log }), "name").map((m) => m._config)

    expect(res.result?.moduleConfigs).to.deep.equal(expectedModuleConfigs)
  })

  it("should include disabled module configs", async () => {
    const garden = await makeTestGardenA()
    const log = garden.log

    garden.setModuleConfigs([
      {
        apiVersion: DEFAULT_API_VERSION,
        allowPublish: false,
        build: { dependencies: [] },
        disabled: true,
        name: "a-disabled",
        include: [],
        path: garden.projectRoot,
        serviceConfigs: [],
        taskConfigs: [],
        spec: {
          services: [
            {
              name: "service-a",
              dependencies: [],
              disabled: false,
              spec: {},
            },
          ],
        },
        testConfigs: [],
        type: "test",
      },
      {
        apiVersion: DEFAULT_API_VERSION,
        allowPublish: false,
        build: { dependencies: [] },
        disabled: false,
        include: [],
        name: "b-enabled",
        path: garden.projectRoot,
        serviceConfigs: [],
        taskConfigs: [],
        spec: {
          services: [
            {
              name: "service-b",
              dependencies: [],
              disabled: false,
              spec: {},
            },
          ],
        },
        testConfigs: [],
        type: "test",
      },
    ])

    const res = await command.action({
      garden,
      log,
      headerLog: log,
      footerLog: log,
      args: {},
      opts: withDefaultGlobalOpts({ "exclude-disabled": false, "resolve": "full" }),
    })

    const expectedModuleConfigs = sortBy(await garden.resolveModules({ log, includeDisabled: true }), "name").map(
      (m) => m._config
    )

    expect(res.result?.moduleConfigs).to.deep.equal(expectedModuleConfigs)
  })

  it("should include disabled service configs", async () => {
    const garden = await makeTestGardenA()
    const log = garden.log

    garden.setModuleConfigs([
      {
        apiVersion: DEFAULT_API_VERSION,
        allowPublish: false,
        build: { dependencies: [] },
        disabled: false,
        name: "enabled",
        include: [],
        path: garden.projectRoot,
        serviceConfigs: [],
        taskConfigs: [],
        spec: {
          services: [
            {
              name: "service-disabled",
              dependencies: [],
              disabled: true,

              spec: {},
            },
            {
              name: "service-enabled",
              dependencies: [],
              disabled: false,

              spec: {},
            },
          ],
          tasks: [
            {
              name: "task-enabled",
              dependencies: [],
              disabled: false,
              command: ["echo", "ok"],
            },
          ],
        },
        testConfigs: [],
        type: "test",
      },
    ])

    const res = await command.action({
      garden,
      log,
      headerLog: log,
      footerLog: log,
      args: {},
      opts: withDefaultGlobalOpts({ "exclude-disabled": false, "resolve": "full" }),
    })

    const expectedModuleConfigs = (await garden.resolveModules({ log, includeDisabled: true })).map((m) => m._config)

    expect(res.result?.moduleConfigs).to.deep.equal(expectedModuleConfigs)
  })

  it("should include disabled task configs", async () => {
    const garden = await makeTestGardenA()
    const log = garden.log

    garden.setModuleConfigs([
      {
        apiVersion: DEFAULT_API_VERSION,
        allowPublish: false,
        build: { dependencies: [] },
        disabled: false,
        name: "enabled",
        include: [],
        path: garden.projectRoot,
        serviceConfigs: [],
        taskConfigs: [],
        spec: {
          services: [
            {
              name: "service",
              dependencies: [],
              disabled: false,
              spec: {},
            },
          ],
          tasks: [
            {
              name: "task-disabled",
              dependencies: [],
              disabled: true,
              command: ["echo", "ok"],
            },
            {
              name: "task-enabled",
              dependencies: [],
              disabled: false,
              command: ["echo", "ok"],
            },
          ],
        },
        testConfigs: [],
        type: "test",
      },
    ])

    const res = await command.action({
      garden,
      log,
      headerLog: log,
      footerLog: log,
      args: {},
      opts: withDefaultGlobalOpts({ "exclude-disabled": false, "resolve": "full" }),
    })

    const expectedModuleConfigs = (await garden.resolveModules({ log, includeDisabled: true })).map((m) => m._config)

    expect(res.result?.moduleConfigs).to.deep.equal(expectedModuleConfigs)
  })

  it("should include disabled test configs", async () => {
    const garden = await makeTestGardenA()
    const log = garden.log

    garden.setModuleConfigs([
      {
        apiVersion: DEFAULT_API_VERSION,
        allowPublish: false,
        build: { dependencies: [] },
        disabled: false,
        name: "enabled",
        include: [],
        path: garden.projectRoot,
        serviceConfigs: [],
        taskConfigs: [],
        spec: {
          services: [
            {
              name: "service",
              dependencies: [],
              disabled: false,
              spec: {},
            },
          ],
          tasks: [
            {
              name: "task-enabled",
              dependencies: [],
              disabled: false,
              command: ["echo", "ok"],
            },
          ],
          tests: [
            {
              name: "test-enabled",
              dependencies: [],
              disabled: false,
              command: ["echo", "ok"],
            },
            {
              name: "test-disabled",
              dependencies: [],
              disabled: true,
              command: ["echo", "ok"],
            },
          ],
        },
        testConfigs: [],
        type: "test",
      },
    ])

    const res = await command.action({
      garden,
      log,
      headerLog: log,
      footerLog: log,
      args: {},
      opts: withDefaultGlobalOpts({ "exclude-disabled": false, "resolve": "full" }),
    })

    const expectedModuleConfigs = (await garden.resolveModules({ log, includeDisabled: true })).map((m) => m._config)

    expect(res.result?.moduleConfigs).to.deep.equal(expectedModuleConfigs)
  })

  context("--exclude-disabled", () => {
    it("should exclude disabled module configs", async () => {
      const garden = await makeTestGardenA()
      const log = garden.log

      garden.setModuleConfigs([
        {
          apiVersion: DEFAULT_API_VERSION,
          allowPublish: false,
          build: { dependencies: [] },
          disabled: true,
          name: "a-disabled",
          include: [],
          path: garden.projectRoot,
          serviceConfigs: [],
          taskConfigs: [],
          spec: {
            services: [
              {
                name: "service-a",
                dependencies: [],
                disabled: false,
                spec: {},
              },
            ],
          },
          testConfigs: [],
          type: "test",
        },
        {
          apiVersion: DEFAULT_API_VERSION,
          allowPublish: false,
          build: { dependencies: [] },
          disabled: false,
          include: [],
          name: "b-enabled",
          path: garden.projectRoot,
          serviceConfigs: [],
          taskConfigs: [],
          spec: {
            services: [
              {
                name: "service-b",
                dependencies: [],
                disabled: false,
                spec: {},
              },
            ],
          },
          testConfigs: [],
          type: "test",
        },
      ])

      const res = await command.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: {},
        opts: withDefaultGlobalOpts({ "exclude-disabled": true, "resolve": "full" }),
      })

      const expectedModuleConfigs = sortBy(await garden.resolveModules({ log }), "name").map((m) => m._config)

      expect(res.result?.moduleConfigs).to.deep.equal(expectedModuleConfigs)
    })

    it("should exclude disabled service configs", async () => {
      const garden = await makeTestGardenA()
      const log = garden.log

      garden.setModuleConfigs([
        {
          apiVersion: DEFAULT_API_VERSION,
          allowPublish: false,
          build: { dependencies: [] },
          disabled: false,
          name: "enabled",
          include: [],
          path: garden.projectRoot,
          serviceConfigs: [],
          taskConfigs: [],
          spec: {
            services: [
              {
                name: "service-disabled",
                dependencies: [],
                disabled: true,

                spec: {},
              },
              {
                name: "service-enabled",
                dependencies: [],
                disabled: false,

                spec: {},
              },
            ],
            tasks: [
              {
                name: "task-enabled",
                dependencies: [],
                disabled: false,
                command: ["echo", "ok"],
              },
            ],
          },
          testConfigs: [],
          type: "test",
        },
      ])

      const res = await command.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: {},
        opts: withDefaultGlobalOpts({ "exclude-disabled": true, "resolve": "full" }),
      })

      const expectedModuleConfigs = (await garden.resolveModules({ log })).map((m) => m._config)
      // Remove the disabled service
      expectedModuleConfigs[0].serviceConfigs = [
        {
          name: "service-enabled",
          dependencies: [],
          disabled: false,
          sourceModuleName: undefined,
          spec: {
            name: "service-enabled",
            dependencies: [],
            disabled: false,
            spec: {},
          },
        },
      ]

      expect(res.result?.moduleConfigs).to.deep.equal(expectedModuleConfigs)
    })

    it("should exclude disabled task configs", async () => {
      const garden = await makeTestGardenA()
      const log = garden.log

      garden.setModuleConfigs([
        {
          apiVersion: DEFAULT_API_VERSION,
          allowPublish: false,
          build: { dependencies: [] },
          disabled: false,
          name: "enabled",
          include: [],
          path: garden.projectRoot,
          serviceConfigs: [],
          taskConfigs: [],
          spec: {
            services: [
              {
                name: "service",
                dependencies: [],
                disabled: false,
                spec: {},
              },
            ],
            tasks: [
              {
                name: "task-disabled",
                dependencies: [],
                disabled: true,
                command: ["echo", "ok"],
              },
              {
                name: "task-enabled",
                dependencies: [],
                disabled: false,
                command: ["echo", "ok"],
              },
            ],
          },
          testConfigs: [],
          type: "test",
        },
      ])

      const res = await command.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: {},
        opts: withDefaultGlobalOpts({ "exclude-disabled": true, "resolve": "full" }),
      })

      const expectedModuleConfigs = (await garden.resolveModules({ log })).map((m) => m._config)
      // Remove the disabled task
      expectedModuleConfigs[0].taskConfigs = [
        {
          name: "task-enabled",
          cacheResult: true,
          dependencies: [],
          disabled: false,
          spec: {
            name: "task-enabled",
            dependencies: [],
            disabled: false,
            timeout: null,
            env: {},
            artifacts: [],
            command: ["echo", "ok"],
          },
          timeout: null,
        },
      ]

      expect(res.result?.moduleConfigs).to.deep.equal(expectedModuleConfigs)
    })

    it("should exclude disabled test configs", async () => {
      const garden = await makeTestGardenA()
      const log = garden.log

      garden.setModuleConfigs([
        {
          apiVersion: DEFAULT_API_VERSION,
          allowPublish: false,
          build: { dependencies: [] },
          disabled: false,
          name: "enabled",
          include: [],
          path: garden.projectRoot,
          serviceConfigs: [],
          taskConfigs: [],
          spec: {
            services: [
              {
                name: "service",
                dependencies: [],
                disabled: false,
                spec: {},
              },
            ],
            tasks: [
              {
                name: "task-enabled",
                dependencies: [],
                disabled: false,
                command: ["echo", "ok"],
              },
            ],
            tests: [
              {
                name: "test-enabled",
                dependencies: [],
                disabled: false,
                command: ["echo", "ok"],
              },
              {
                name: "test-disabled",
                dependencies: [],
                disabled: true,
                command: ["echo", "ok"],
              },
            ],
          },
          testConfigs: [],
          type: "test",
        },
      ])

      const res = await command.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: {},
        opts: withDefaultGlobalOpts({ "exclude-disabled": true, "resolve": "full" }),
      })

      const expectedModuleConfigs = (await garden.resolveModules({ log })).map((m) => m._config)
      // Remove the disabled test
      expectedModuleConfigs[0].testConfigs = [
        {
          name: "test-enabled",
          dependencies: [],
          disabled: false,
          spec: {
            name: "test-enabled",
            dependencies: [],
            disabled: false,
            timeout: null,
            artifacts: [],
            command: ["echo", "ok"],
            env: {},
          },
          timeout: null,
        },
      ]

      expect(res.result?.moduleConfigs).to.deep.equal(expectedModuleConfigs)
    })
  })

  context("resolve=partial", () => {
    it("should return raw module configs instead of fully resolved module configs", async () => {
      const garden = await makeTestGardenA()
      const log = garden.log

      const rawConfigs = [
        {
          apiVersion: DEFAULT_API_VERSION,
          allowPublish: false,
          build: { dependencies: [] },
          disabled: false,
          name: "enabled",
          include: [],
          path: garden.projectRoot,
          serviceConfigs: [],
          taskConfigs: [],
          spec: {
            services: [],
            tasks: [],
            tests: [
              {
                name: "test-enabled",
                dependencies: [],
                disabled: false,
                command: ["${project.name}"],
              },
            ],
          },
          testConfigs: [],
          type: "test",
        },
      ]

      garden.setModuleConfigs(rawConfigs)

      const res = await command.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: {},
        opts: withDefaultGlobalOpts({ "exclude-disabled": false, "resolve": "partial" }),
      })

      expect(res.result?.moduleConfigs).to.deep.equal(rawConfigs)
    })

    it("should return raw provider configs instead of fully resolved providers", async () => {
      const garden = await makeTestGardenA()
      const log = garden.log

      const res = await command.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: {},
        opts: withDefaultGlobalOpts({ "exclude-disabled": false, "resolve": "partial" }),
      })

      expect(res.result!.providers).to.eql(garden.getRawProviderConfigs())
    })

    it("should not resolve providers", async () => {
      const garden = await makeTestGardenA()
      const log = garden.log

      await command.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: {},
        opts: withDefaultGlobalOpts({ "exclude-disabled": false, "resolve": "partial" }),
      })

      expect(garden["resolvedProviders"]).to.eql({})
    })
  })
})
