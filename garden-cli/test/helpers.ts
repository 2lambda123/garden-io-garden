/*
 * Copyright (C) 2018 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import * as td from "testdouble"
import { resolve, join } from "path"
import { remove } from "fs-extra"
import { containerModuleSpecSchema } from "../src/plugins/container"
import { testGenericModule, buildGenericModule } from "../src/plugins/generic"
import { TaskResults } from "../src/task-graph"
import {
  validate,
} from "../src/config/common"
import {
  GardenPlugin,
  PluginActions,
  PluginFactory,
  ModuleActions,
} from "../src/types/plugin/plugin"
import { Garden } from "../src/garden"
import { ModuleConfig } from "../src/config/module"
import { mapValues } from "lodash"
import {
  DeleteConfigParams,
  GetConfigParams,
  ParseModuleParams,
  RunModuleParams,
  RunServiceParams,
  SetConfigParams,
} from "../src/types/plugin/params"
import {
  helpers,
} from "../src/vcs/git"
import {
  ModuleVersion,
} from "../src/vcs/base"
import { GARDEN_DIR_NAME } from "../src/constants"

export const dataDir = resolve(__dirname, "data")
export const testNow = new Date()
export const testModuleVersionString = "1234512345"
export const testModuleVersion: ModuleVersion = {
  versionString: testModuleVersionString,
  dirtyTimestamp: null,
  dependencyVersions: {},
}

export function getDataDir(name: string) {
  return resolve(dataDir, name)
}

export async function profileBlock(description: string, block: () => Promise<any>) {
  const startTime = new Date().getTime()
  const result = await block()
  const executionTime = (new Date().getTime()) - startTime
  console.log(description, "took", executionTime, "ms")
  return result
}

export const projectRootA = getDataDir("test-project-a")

export const testPlugin: PluginFactory = (): GardenPlugin => {
  const _config = {}

  return {
    actions: {
      async configureEnvironment() {
        return {}
      },

      async setConfig({ key, value }: SetConfigParams) {
        _config[key.join(".")] = value
        return {}
      },

      async getConfig({ key }: GetConfigParams) {
        return { value: _config[key.join(".")] || null }
      },

      async deleteConfig({ key }: DeleteConfigParams) {
        const k = key.join(".")
        if (_config[k]) {
          delete _config[k]
          return { found: true }
        } else {
          return { found: false }
        }
      },
    },
    moduleActions: {
      test: {
        testModule: testGenericModule,

        async parseModule({ moduleConfig }: ParseModuleParams) {
          moduleConfig.spec = validate(
            moduleConfig.spec,
            containerModuleSpecSchema,
            { context: `test module ${moduleConfig.name}` },
          )

          // validate services
          moduleConfig.serviceConfigs = moduleConfig.spec.services.map(spec => ({
            name: spec.name,
            dependencies: spec.dependencies,
            outputs: spec.outputs,
            spec,
          }))

          moduleConfig.testConfigs = moduleConfig.spec.tests.map(t => ({
            name: t.name,
            dependencies: t.dependencies,
            spec: t,
            timeout: t.timeout,
          }))

          return moduleConfig
        },

        buildModule: buildGenericModule,

        async runModule(params: RunModuleParams) {
          const version = await params.module.version

          return {
            moduleName: params.module.name,
            command: params.command,
            completedAt: testNow,
            output: "OK",
            version,
            startedAt: testNow,
            success: true,
          }
        },

        async runService({ ctx, service, interactive, runtimeContext, silent, timeout }: RunServiceParams) {
          return ctx.runModule({
            moduleName: service.module.name,
            command: [service.name],
            interactive,
            runtimeContext,
            silent,
            timeout,
          })
        },

        async getServiceStatus() { return {} },
        async deployService() { return {} },
      },
    },
  }
}
testPlugin.pluginName = "test-plugin"

export const testPluginB: PluginFactory = async (params) => {
  const plugin = await testPlugin(params)
  plugin.moduleActions = {
    test: plugin.moduleActions!.test,
  }
  return plugin
}
testPluginB.pluginName = "test-plugin-b"

export const testPluginC: PluginFactory = async (params) => {
  const plugin = await testPlugin(params)
  plugin.moduleActions = {
    "test-c": plugin.moduleActions!.test,
  }
  return plugin
}
testPluginC.pluginName = "test-plugin-c"

export const defaultModuleConfig: ModuleConfig = {
  type: "test",
  name: "test",
  path: "bla",
  allowPush: false,
  variables: {},
  build: { command: [], dependencies: [] },
  spec: {
    services: [
      {
        name: "test-service",
        dependencies: [],
      },
    ],
  },
  serviceConfigs: [],
  testConfigs: [],
}

export const makeTestModule = (params: Partial<ModuleConfig> = {}) => {
  return { ...defaultModuleConfig, ...params }
}

export const makeTestGarden = async (projectRoot: string, extraPlugins: PluginFactory[] = []) => {
  const testPlugins: PluginFactory[] = [
    testPlugin,
    testPluginB,
    testPluginC,
  ]
  const plugins: PluginFactory[] = testPlugins.concat(extraPlugins)

  return Garden.factory(projectRoot, { plugins })
}

export const makeTestContext = async (projectRoot: string, extraPlugins: PluginFactory[] = []) => {
  const garden = await makeTestGarden(projectRoot, extraPlugins)
  return garden.getPluginContext()
}

export const makeTestGardenA = async (extraPlugins: PluginFactory[] = []) => {
  return makeTestGarden(projectRootA, extraPlugins)
}

export const makeTestContextA = async (extraPlugins: PluginFactory[] = []) => {
  const garden = await makeTestGardenA(extraPlugins)
  return garden.getPluginContext()
}

export function stubAction<T extends keyof PluginActions>(
  garden: Garden, pluginName: string, type: T, handler?: PluginActions[T],
) {
  return td.replace(garden["actionHandlers"][type], pluginName, handler)
}

export function stubModuleAction<T extends keyof ModuleActions<any>>(
  garden: Garden, moduleType: string, pluginName: string, actionType: T, handler: ModuleActions<any>[T],
) {
  handler["actionType"] = actionType
  handler["pluginName"] = pluginName
  handler["moduleType"] = moduleType
  return td.replace(garden["moduleActionHandlers"][actionType][moduleType], pluginName, handler)
}

export async function expectError(fn: Function, typeOrCallback: string | ((err: any) => void)) {
  try {
    await fn()
  } catch (err) {
    if (typeof typeOrCallback === "function") {
      return typeOrCallback(err)
    } else {
      if (!err.type) {
        const newError = Error(`Expected GardenError with type ${typeOrCallback}, got: ${err}`)
        newError.stack = err.stack
        throw newError
      }
      if (err.type !== typeOrCallback) {
        const newError = Error(`Expected ${typeOrCallback} error, got: ${err.type} error`)
        newError.stack = err.stack
        throw newError
      }
    }
    return
  }

  if (typeof typeOrCallback === "string") {
    throw new Error(`Expected ${typeOrCallback} error (got no error)`)
  } else {
    throw new Error(`Expected error (got no error)`)
  }
}

export function taskResultOutputs(results: TaskResults) {
  return mapValues(results, r => r.output)
}

export const cleanProject = async (projectRoot: string) => {
  return remove(join(projectRoot, GARDEN_DIR_NAME))
}

export function stubGitCli() {
  td.replace(helpers, "gitCli", () => async () => "")
}

/**
 * Prevents git cloning. Use if creating a Garden instance with test-project-ext-module-sources
 * or test-project-ext-project-sources as project root.
 */
export function stubExtSources(garden: Garden) {
  stubGitCli()
  const getRemoteSourcesDirName = td.replace(garden.vcs, "getRemoteSourcesDirName")

  td.when(getRemoteSourcesDirName("module")).thenReturn(join("mock-dot-garden", "sources", "module"))
  td.when(getRemoteSourcesDirName("project")).thenReturn(join("mock-dot-garden", "sources", "project"))
}
