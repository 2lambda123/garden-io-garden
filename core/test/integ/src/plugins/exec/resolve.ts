/*
 * Copyright (C) 2018-2023 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { expect } from "chai"
import { readFile } from "fs-extra"
import { join } from "node:path"
import { getDataDir, makeTestGarden, TestGarden } from "../../../../helpers"

describe("exec provider initialization cache behaviour", () => {
  let gardenOne: TestGarden
  let tmpDir: string
  let fileLocation: string

  beforeEach(async () => {
    gardenOne = await makeTestGarden(getDataDir("exec-provider-cache"), { environmentString: "one" })

    tmpDir = join(await gardenOne.getRepoRoot(), "project")
    fileLocation = join(tmpDir, "theFile")

    await gardenOne.resolveProvider(gardenOne.log, "exec")
  })

  it("writes the environment name to theFile as configured in the initScript", async () => {
    const contents = await readFile(fileLocation, { encoding: "utf-8" })

    expect(contents).equal("one\n")
  })

  it("overwrites theFile when changing environments", async () => {
    let contents = await readFile(fileLocation, { encoding: "utf-8" })
    expect(contents).equal("one\n")

    const gardenTwo = await makeTestGarden(tmpDir, { environmentString: "two", noTempDir: true })
    await gardenTwo.resolveProvider(gardenTwo.log, "exec")

    contents = await readFile(fileLocation, { encoding: "utf-8" })
    expect(contents).equal("two\n")
  })

  it("still overwrites theFile when changing environments back", async () => {
    let contents = await readFile(fileLocation, { encoding: "utf-8" })
    expect(contents).equal("one\n")

    const gardenTwo = await makeTestGarden(tmpDir, { environmentString: "two", noTempDir: true })
    await gardenTwo.resolveProvider(gardenTwo.log, "exec")

    contents = await readFile(fileLocation, { encoding: "utf-8" })
    expect(contents).equal("two\n")

    const gardenOneAgain = await makeTestGarden(tmpDir, { environmentString: "one", noTempDir: true })
    await gardenOneAgain.resolveProvider(gardenOneAgain.log, "exec")

    contents = await readFile(fileLocation, { encoding: "utf-8" })
    expect(contents).equal("one\n")
  })
})
