/*
 * Copyright (C) 2018-2022 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { expect } from "chai"
import { getMatchingDeployNames } from "../../../../src/commands/helpers"
import { ConfigGraph } from "../../../../src/graph/config-graph"
import { makeTestGardenA } from "../../../helpers"

// TODO-G2: rename test cases to match the new graph model semantics
describe("getMatchingServiceNames", () => {
  let graph: ConfigGraph

  before(async () => {
    const garden = await makeTestGardenA()
    graph = await garden.getConfigGraph({ log: garden.log, emit: false })
  })

  it("should return all services if --sync=* is set", async () => {
    const result = getMatchingDeployNames(["*"], graph)
    expect(result).to.eql(graph.getDeploys().map((s) => s.name))
  })

  it("should return all services if --sync is set with no value", async () => {
    const result = getMatchingDeployNames([], graph)
    expect(result).to.eql(graph.getDeploys().map((s) => s.name))
  })

  it("should return specific service if --sync is set with a service name", async () => {
    const result = getMatchingDeployNames(["service-a"], graph)
    expect(result).to.eql(["service-a"])
  })
})
