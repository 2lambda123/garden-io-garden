import { expect } from "chai"
import * as td from "testdouble"
import { join, resolve } from "path"
import { Garden } from "../../src/garden"
import { detectCycles } from "../../src/util/detectCycles"
import {
  dataDir,
  expectError,
  makeTestGarden,
  makeTestGardenA,
  makeTestModule,
  projectRootA,
  testPlugin,
  testPluginB,
  stubExtSources,
  getDataDir,
  cleanProject,
  stubGitCli,
  testModuleVersion,
} from "../helpers"
import { getNames } from "../../src/util/util"
import { MOCK_CONFIG } from "../../src/cli/cli"
import { LinkedSource } from "../../src/config-store"
import { ModuleVersion } from "../../src/vcs/base"

describe("Garden", () => {
  beforeEach(async () => {
    td.replace(Garden.prototype, "resolveVersion", async () => testModuleVersion)
  })

  describe("factory", () => {
    it("should throw when initializing with missing plugins", async () => {
      await expectError(async () => await Garden.factory(projectRootA), "configuration")
    })

    it("should initialize and add the action handlers for a plugin", async () => {
      const garden = await makeTestGardenA()

      expect(garden.actionHandlers.configureEnvironment["test-plugin"]).to.be.ok
      expect(garden.actionHandlers.configureEnvironment["test-plugin-b"]).to.be.ok
    })

    it("should initialize with MOCK_CONFIG", async () => {
      const garden = await Garden.factory("./", { config: MOCK_CONFIG })
      expect(garden).to.be.ok
    })

    it("should throw if registering same plugin twice", async () => {
      try {
        await Garden.factory(projectRootA, {
          plugins: ["test-plugin", "test-plugin"],
        })
      } catch (err) {
        expect(err.type).to.equal("configuration")
        return
      }

      throw new Error("Expected error")
    })

    it("should parse and resolve the config from the project root", async () => {
      const garden = await makeTestGardenA()

      expect(garden.projectName).to.equal("test-project-a")
      expect(garden.environmentConfig).to.eql({
        name: "local",
        providers: [
          { name: "test-plugin" },
          { name: "test-plugin-b" },
        ],
        variables: {
          some: "variable",
        },
      })
    })

    it("should resolve templated env variables in project config", async () => {
      process.env.TEST_PROVIDER_TYPE = "test-plugin"
      process.env.TEST_VARIABLE = "banana"

      const projectRoot = join(__dirname, "..", "data", "test-project-templated")

      const garden = await makeTestGarden(projectRoot)

      delete process.env.TEST_PROVIDER_TYPE
      delete process.env.TEST_VARIABLE

      expect(garden.environmentConfig).to.eql({
        name: "local",
        providers: [
          { name: "test-plugin" },
        ],
        variables: {
          some: "banana",
          "service-a-build-command": "OK",
        },
      })
    })

    it("should optionally set a namespace with the dot separator", async () => {
      const garden = await Garden.factory(
        projectRootA, { env: "local.mynamespace", plugins: [testPlugin, testPluginB] },
      )

      const { name, namespace } = garden.getEnvironment()
      expect(name).to.equal("local")
      expect(namespace).to.equal("mynamespace")
    })

    it("should split environment and namespace on the first dot", async () => {
      const garden = await Garden.factory(
        projectRootA, { env: "local.mynamespace.2", plugins: [testPlugin, testPluginB] },
      )

      const { name, namespace } = garden.getEnvironment()
      expect(name).to.equal("local")
      expect(namespace).to.equal("mynamespace.2")
    })

    it("should throw if the specified environment isn't configured", async () => {
      await expectError(async () => Garden.factory(projectRootA, { env: "bla" }), "parameter")
    })

    it("should throw if namespace starts with 'garden-'", async () => {
      await expectError(async () => Garden.factory(projectRootA, { env: "garden-bla" }), "parameter")
    })

    it("should throw if no provider is configured for the environment", async () => {
      await expectError(async () => Garden.factory(projectRootA, { env: "other" }), "configuration")
    })

    it("should throw if plugin module exports invalid name", async () => {
      const pluginPath = join(dataDir, "plugins", "invalid-exported-name.ts")
      const projectRoot = join(dataDir, "test-project-empty")
      await expectError(async () => Garden.factory(projectRoot, { plugins: [pluginPath] }), "plugin")
    })

    it("should throw if plugin module name is not a valid identifier", async () => {
      const pluginPath = join(dataDir, "plugins", "invalidModuleName.ts")
      const projectRoot = join(dataDir, "test-project-empty")
      await expectError(async () => Garden.factory(projectRoot, { plugins: [pluginPath] }), "plugin")
    })

    it("should throw if plugin module doesn't contain factory function", async () => {
      const pluginPath = join(dataDir, "plugins", "missing-factory.ts")
      const projectRoot = join(dataDir, "test-project-empty")
      await expectError(async () => Garden.factory(projectRoot, { plugins: [pluginPath] }), "plugin")
    })
  })

  describe("getEnvironment", () => {
    it("should get the active environment for the context", async () => {
      const garden = await makeTestGardenA()

      const { name, namespace } = garden.getEnvironment()
      expect(name).to.equal("local")
      expect(namespace).to.equal("default")
    })
  })

  describe("getModules", () => {
    it("should scan and return all registered modules in the context", async () => {
      const garden = await makeTestGardenA()
      const modules = await garden.getModules()

      expect(getNames(modules).sort()).to.eql(["module-a", "module-b", "module-c"])
    })

    it("should optionally return specified modules in the context", async () => {
      const garden = await makeTestGardenA()
      const modules = await garden.getModules(["module-b", "module-c"])

      expect(getNames(modules).sort()).to.eql(["module-b", "module-c"])
    })

    it("should throw if named module is missing", async () => {
      const garden = await makeTestGardenA()

      try {
        await garden.getModules(["bla"])
      } catch (err) {
        expect(err.type).to.equal("parameter")
        return
      }

      throw new Error("Expected error")
    })
  })

  describe("getServices", () => {
    it("should scan for modules and return all registered services in the context", async () => {
      const garden = await makeTestGardenA()
      const services = await garden.getServices()

      expect(getNames(services).sort()).to.eql(["service-a", "service-b", "service-c"])
    })

    it("should optionally return specified services in the context", async () => {
      const garden = await makeTestGardenA()
      const services = await garden.getServices(["service-b", "service-c"])

      expect(getNames(services).sort()).to.eql(["service-b", "service-c"])
    })

    it("should throw if named service is missing", async () => {
      const garden = await makeTestGardenA()

      try {
        await garden.getServices(["bla"])
      } catch (err) {
        expect(err.type).to.equal("parameter")
        return
      }

      throw new Error("Expected error")
    })
  })

  describe("getService", () => {
    it("should return the specified service", async () => {
      const garden = await makeTestGardenA()
      const service = await garden.getService("service-b")

      expect(service.name).to.equal("service-b")
    })

    it("should throw if service is missing", async () => {
      const garden = await makeTestGardenA()

      try {
        await garden.getServices(["bla"])
      } catch (err) {
        expect(err.type).to.equal("parameter")
        return
      }

      throw new Error("Expected error")
    })
  })

  describe("scanModules", () => {
    // TODO: assert that gitignore in project root is respected

    afterEach(() => {
      td.reset()
    })

    it("should scan the project root for modules and add to the context", async () => {
      const garden = await makeTestGardenA()
      await garden.scanModules()

      const modules = await garden.getModules(undefined, true)
      expect(getNames(modules).sort()).to.eql(["module-a", "module-b", "module-c"])
    })

    it("should scan and add modules for projects with external project sources", async () => {
      const garden = await makeTestGarden(resolve(dataDir, "test-project-ext-project-sources"))
      stubExtSources(garden)
      await garden.scanModules()

      const modules = await garden.getModules(undefined, true)
      expect(getNames(modules).sort()).to.eql(["module-a", "module-b", "module-c"])
    })

    describe("detectCircularDependencies", () => {
      it("should throw an exception when circular dependencies are present", async () => {
        const circularProjectRoot = join(__dirname, "..", "data", "test-project-circular-deps")
        const garden = await makeTestGarden(circularProjectRoot)
        await expectError(
          async () => await garden.scanModules(),
          "configuration")
      })

      it("should not throw an exception when no circular dependencies are present", async () => {
        const nonCircularProjectRoot = join(__dirname, "..", "data", "test-project-b")
        const garden = await makeTestGarden(nonCircularProjectRoot)
        expect(async () => { await garden.scanModules() }).to.not.throw()
      })
    })

    describe("detectCycles", () => {
      it("should detect self-to-self cycles", () => {
        const cycles = detectCycles({
          a: { a: { distance: 1, next: "a" } },
        }, ["a"])

        expect(cycles).to.deep.eq([["a"]])
      })

      it("should preserve dependency order when returning cycles", () => {
        const cycles = detectCycles({
          foo: { bar: { distance: 1, next: "bar" } },
          bar: { baz: { distance: 1, next: "baz" } },
          baz: { foo: { distance: 1, next: "foo" } },
        }, ["foo", "bar", "baz"])

        expect(cycles).to.deep.eq([["foo", "bar", "baz"]])
      })
    })
  })

  describe("addModule", () => {
    it("should add the given module and its services to the context", async () => {
      const garden = await makeTestGardenA()

      const testModule = makeTestModule()
      await garden.addModule(testModule)

      const modules = await garden.getModules(undefined, true)
      expect(getNames(modules)).to.eql(["test"])

      const services = await garden.getServices(undefined, true)
      expect(getNames(services)).to.eql(["test-service"])
    })

    it("should throw when adding module twice without force parameter", async () => {
      const garden = await makeTestGardenA()

      const testModule = makeTestModule()
      await garden.addModule(testModule)

      try {
        await garden.addModule(testModule)
      } catch (err) {
        expect(err.type).to.equal("configuration")
        return
      }

      throw new Error("Expected error")
    })

    it("should allow adding module multiple times with force parameter", async () => {
      const garden = await makeTestGardenA()

      let testModule = makeTestModule()
      await garden.addModule(testModule)

      testModule = makeTestModule()
      await garden.addModule(testModule, true)

      const modules = await garden.getModules(undefined, true)
      expect(getNames(modules)).to.eql(["test"])
    })

    it("should throw if a service is added twice without force parameter", async () => {
      const garden = await makeTestGardenA()

      const testModule = makeTestModule()
      const testModuleB = makeTestModule({ name: "test-b" })
      await garden.addModule(testModule)

      try {
        await garden.addModule(testModuleB)
      } catch (err) {
        expect(err.type).to.equal("configuration")
        return
      }

      throw new Error("Expected error")
    })

    it("should allow adding service multiple times with force parameter", async () => {
      const garden = await makeTestGardenA()

      const testModule = makeTestModule()
      const testModuleB = makeTestModule({ name: "test-b" })
      await garden.addModule(testModule)
      await garden.addModule(testModuleB, true)

      const services = await garden.getServices(undefined, true)
      expect(getNames(services)).to.eql(["test-service"])
    })
  })

  describe("resolveModule", () => {
    it("should return named module", async () => {
      const garden = await makeTestGardenA()
      await garden.scanModules()

      const module = await garden.resolveModule("module-a")
      expect(module!.name).to.equal("module-a")
    })

    it("should throw if named module is requested and not available", async () => {
      const garden = await makeTestGardenA()

      try {
        await garden.resolveModule("module-a")
      } catch (err) {
        expect(err.type).to.equal("configuration")
        return
      }

      throw new Error("Expected error")
    })

    it("should resolve module by absolute path", async () => {
      const garden = await makeTestGardenA()
      const path = join(projectRootA, "module-a")

      const module = await garden.resolveModule(path)
      expect(module!.name).to.equal("module-a")
    })

    it("should resolve module by relative path to project root", async () => {
      const garden = await makeTestGardenA()

      const module = await garden.resolveModule("./module-a")
      expect(module!.name).to.equal("module-a")
    })

    it("should resolve module path to external sources dir if module has a remote source", async () => {
      const projectRoot = resolve(dataDir, "test-project-ext-module-sources")
      const garden = await makeTestGarden(projectRoot)
      stubGitCli()

      const module = await garden.resolveModule("./module-a")
      expect(module!.path).to.equal(join(projectRoot, ".garden", "sources", "module", "module-a"))
    })
  })

  describe("getActionHandlers", () => {
    it("should return all handlers for a type", async () => {
      const garden = await makeTestGardenA()

      const handlers = garden.getActionHandlers("configureEnvironment")

      expect(Object.keys(handlers)).to.eql([
        "test-plugin",
        "test-plugin-b",
      ])
    })
  })

  describe("getModuleActionHandlers", () => {
    it("should return all handlers for a type", async () => {
      const garden = await makeTestGardenA()

      const handlers = garden.getModuleActionHandlers({ actionType: "buildModule", moduleType: "generic" })

      expect(Object.keys(handlers)).to.eql([
        "generic",
      ])
    })
  })

  describe("getActionHandler", () => {
    it("should return last configured handler for specified action type", async () => {
      const garden = await makeTestGardenA()

      const handler = garden.getActionHandler({ actionType: "configureEnvironment" })

      expect(handler["actionType"]).to.equal("configureEnvironment")
      expect(handler["pluginName"]).to.equal("test-plugin-b")
    })

    it("should optionally filter to only handlers for the specified module type", async () => {
      const garden = await makeTestGardenA()

      const handler = garden.getActionHandler({ actionType: "configureEnvironment" })

      expect(handler["actionType"]).to.equal("configureEnvironment")
      expect(handler["pluginName"]).to.equal("test-plugin-b")
    })

    it("should throw if no handler is available", async () => {
      const garden = await makeTestGardenA()
      await expectError(() => garden.getActionHandler({ actionType: "destroyEnvironment" }), "parameter")
    })
  })

  describe("getModuleActionHandler", () => {
    it("should return last configured handler for specified module action type", async () => {
      const garden = await makeTestGardenA()

      const handler = garden.getModuleActionHandler({ actionType: "deployService", moduleType: "test" })

      expect(handler["actionType"]).to.equal("deployService")
      expect(handler["pluginName"]).to.equal("test-plugin-b")
    })

    it("should throw if no handler is available", async () => {
      const garden = await makeTestGardenA()
      await expectError(
        () => garden.getModuleActionHandler({ actionType: "execInService", moduleType: "container" }),
        "parameter",
      )
    })
  })

  describe("resolveModuleDependencies", () => {
    it("should resolve build dependencies", async () => {
      const garden = await makeTestGardenA()
      const modules = await garden.resolveModuleDependencies([{ name: "module-c", copy: [] }], [])
      expect(getNames(modules)).to.eql(["module-a", "module-b", "module-c"])
    })

    it("should resolve service dependencies", async () => {
      const garden = await makeTestGardenA()
      const modules = await garden.resolveModuleDependencies([], ["service-b"])
      expect(getNames(modules)).to.eql(["module-a", "module-b"])
    })

    it("should combine module and service dependencies", async () => {
      const garden = await makeTestGardenA()
      const modules = await garden.resolveModuleDependencies([{ name: "module-b", copy: [] }], ["service-c"])
      expect(getNames(modules)).to.eql(["module-a", "module-b", "module-c"])
    })
  })

  describe("resolveVersion", () => {
    beforeEach(() => td.reset())

    it("should return result from cache if available", async () => {
      const garden = await makeTestGardenA()
      const module = await garden.getModule("module-a")
      const version: ModuleVersion = {
        versionString: "banana",
        dirtyTimestamp: 987654321,
        dependencyVersions: {},
      }
      garden.cache.set(["moduleVersions", module.name], version, module.cacheContext)

      const result = await garden.resolveVersion("module-a", [])

      expect(result).to.eql(version)
    })

    it("should otherwise return version from VCS handler", async () => {
      const garden = await makeTestGardenA()
      await garden.scanModules()

      garden.cache.delete(["moduleVersions", "module-b"])

      const resolveStub = td.replace(garden.vcs, "resolveVersion")
      const version: ModuleVersion = {
        versionString: "banana",
        dirtyTimestamp: 987654321,
        dependencyVersions: {},
      }

      td.when(resolveStub(), { ignoreExtraArgs: true }).thenResolve(version)

      const result = await garden.resolveVersion("module-b", [])

      expect(result).to.eql(version)
    })

    it("should ignore cache if force=true", async () => {
      const garden = await makeTestGardenA()
      const module = await garden.getModule("module-a")
      const version: ModuleVersion = {
        versionString: "banana",
        dirtyTimestamp: 987654321,
        dependencyVersions: {},
      }
      garden.cache.set(["moduleVersions", module.name], version, module.cacheContext)

      const result = await garden.resolveVersion("module-a", [], true)

      expect(result).to.not.eql(version)
    })
  })

  describe("loadExtSourcePath", () => {

    let projectRoot: string

    const makeGardenContext = async (root) => {
      const ctx = await makeTestGarden(root)
      stubGitCli()
      return ctx
    }

    afterEach(async () => {
      td.reset()
      await cleanProject(projectRoot)
    })

    it("should return the path to the project source if source type is project", async () => {
      projectRoot = getDataDir("test-project-ext-project-sources")
      const ctx = await makeGardenContext(projectRoot)
      const path = await ctx.loadExtSourcePath({ name: "source-a", repositoryUrl: "", sourceType: "project" })
      expect(path).to.equal(join(projectRoot, ".garden", "sources", "project", "source-a"))
    })

    it("should return the path to the module source if source type is module", async () => {
      projectRoot = getDataDir("test-project-ext-module-sources")
      const ctx = await makeGardenContext(projectRoot)
      const path = await ctx.loadExtSourcePath({ name: "module-a", repositoryUrl: "", sourceType: "module" })
      expect(path).to.equal(join(projectRoot, ".garden", "sources", "module", "module-a"))
    })

    it("should return the local path of the project source if linked", async () => {
      projectRoot = getDataDir("test-project-ext-project-sources")
      const ctx = await makeGardenContext(projectRoot)
      const localPath = join(projectRoot, "mock-local-path", "source-a")

      const linked: LinkedSource[] = [{
        name: "source-a",
        path: localPath,
      }]
      await ctx.localConfigStore.set(["linkedProjectSources"], linked)

      const path = await ctx.loadExtSourcePath({ name: "source-a", repositoryUrl: "", sourceType: "project" })

      expect(path).to.equal(join(projectRoot, "mock-local-path", "source-a"))
    })

    it("should return the local path of the module source if linked", async () => {
      projectRoot = getDataDir("test-project-ext-module-sources")
      const ctx = await makeGardenContext(projectRoot)
      const localPath = join(projectRoot, "mock-local-path", "module-a")

      const linked: LinkedSource[] = [{
        name: "module-a",
        path: localPath,
      }]
      await ctx.localConfigStore.set(["linkedModuleSources"], linked)

      const path = await ctx.loadExtSourcePath({ name: "module-a", repositoryUrl: "", sourceType: "module" })

      expect(path).to.equal(join(projectRoot, "mock-local-path", "module-a"))
    })

  })
})
