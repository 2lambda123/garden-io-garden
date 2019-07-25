/*
 * Copyright (C) 2018 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { expect } from "chai"
import { join } from "path"
import { mkdirp, pathExists } from "fs-extra"

import {
  getDataDir,
  expectError,
  stubExtSources,
  makeTestGarden,
  withDefaultGlobalOpts,
} from "../../../helpers"
import { UpdateRemoteSourcesCommand } from "../../../../src/commands/update-remote/sources"
import { UpdateRemoteModulesCommand } from "../../../../src/commands/update-remote/modules"
import { Garden } from "../../../../src/garden"
import { LogEntry } from "../../../../src/logger/log-entry"
import * as td from "testdouble"
import { ModuleVersion } from "../../../../src/vcs/vcs"

describe("UpdateRemoteCommand", () => {
  describe("UpdateRemoteSourcesCommand", () => {
    let garden: Garden
    let log: LogEntry

    beforeEach(async () => {
      garden = await makeTestGarden(projectRoot)
      log = garden.log
      stubExtSources(garden)
    })

    const projectRoot = getDataDir("test-project-ext-project-sources")
    const cmd = new UpdateRemoteSourcesCommand()

    it("should update all project sources", async () => {
      const { result } = await cmd.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: { sources: undefined },
        opts: withDefaultGlobalOpts({}),
      })
      expect(result!.map(s => s.name).sort()).to.eql(["source-a", "source-b", "source-c"])
    })

    it("should update the specified project sources", async () => {
      const { result } = await cmd.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: { sources: ["source-a"] },
        opts: withDefaultGlobalOpts({}),
      })
      expect(result!.map(s => s.name).sort()).to.eql(["source-a"])
    })

    it("should remove stale remote project sources", async () => {
      const stalePath = join(garden.gardenDirPath, "sources", "project", "stale-source")
      await mkdirp(stalePath)
      await cmd.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: { sources: undefined },
        opts: withDefaultGlobalOpts({}),
      })
      expect(await pathExists(stalePath)).to.be.false
    })

    it("should throw if project source is not found", async () => {
      await expectError(
        async () => (
          await cmd.action({
            garden,
            log,
            headerLog: log,
            footerLog: log,
            args: { sources: ["banana"] },
            opts: withDefaultGlobalOpts({}),
          })
        ),
        "parameter",
      )
    })
  })

  describe("UpdateRemoteModulesCommand", () => {
    let garden: Garden
    let log: LogEntry

    const dummyVersion: ModuleVersion = {
      versionString: "foo",
      dependencyVersions: {},
      files: [],
    }

    beforeEach(async () => {
      garden = await makeTestGarden(projectRoot)
      log = garden.log
      stubExtSources(garden)
      const resolveVersion = td.replace(garden, "resolveVersion")
      td.when(resolveVersion("module-a", [])).thenResolve(dummyVersion)
      td.when(resolveVersion("module-b", [])).thenResolve(dummyVersion)
      td.when(resolveVersion("module-c", [])).thenResolve(dummyVersion)
    })

    const projectRoot = getDataDir("test-project-ext-module-sources")
    const cmd = new UpdateRemoteModulesCommand()

    it("should update all modules sources", async () => {
      const { result } = await cmd.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: { modules: undefined },
        opts: withDefaultGlobalOpts({}),
      })
      expect(result!.map(s => s.name).sort()).to.eql(["module-a", "module-b", "module-c"])
    })

    it("should update the specified module sources", async () => {
      const { result } = await cmd.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: { modules: ["module-a"] },
        opts: withDefaultGlobalOpts({}),
      })
      expect(result!.map(s => s.name).sort()).to.eql(["module-a"])
    })

    it("should remove stale remote module sources", async () => {
      const stalePath = join(garden.gardenDirPath, "sources", "module", "stale-source")
      await mkdirp(stalePath)
      await cmd.action({
        garden,
        log,
        headerLog: log,
        footerLog: log,
        args: { modules: undefined },
        opts: withDefaultGlobalOpts({}),
      })
      expect(await pathExists(stalePath)).to.be.false
    })

    it("should throw if project source is not found", async () => {
      await expectError(
        async () => (
          await cmd.action({
            garden,
            log,
            headerLog: log,
            footerLog: log,
            args: { modules: ["banana"] },
            opts: withDefaultGlobalOpts({}),
          })
        ),
        "parameter",
      )
    })
  })
})
