/*
 * Copyright (C) 2018-2023 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { expect } from "chai"

import { TestGarden } from "../../../../../helpers"
import { ConfigGraph } from "../../../../../../src/graph/config-graph"
import { getKubernetesTestGarden } from "./common"
import { clearRunResult } from "../../../../../../src/plugins/kubernetes/run-results"
import { TestTask } from "../../../../../../src/tasks/test"

describe("kubernetes-type exec Test", () => {
  let garden: TestGarden
  let graph: ConfigGraph

  before(async () => {
    garden = await getKubernetesTestGarden()
  })

  beforeEach(async () => {
    graph = await garden.getConfigGraph({ log: garden.log, emit: false })
  })

  it("should run a basic Test", async () => {
    const action = graph.getTest("echo-test-exec")

    const testTask = new TestTask({
      garden,
      graph,
      action,
      log: garden.log,
      force: true,
      forceBuild: false,
    })

    // Clear any existing Run result
    const provider = await garden.resolveProvider(garden.log, "local-kubernetes")
    const ctx = await garden.getPluginContext({ provider, templateContext: undefined, events: undefined })
    await clearRunResult({ ctx, log: garden.log, action })

    const results = await garden.processTasks({ tasks: [testTask], throwOnError: true })
    const result = results.results.getResult(testTask)

    expect(result).to.exist
    expect(result?.result).to.exist
    expect(result?.outputs).to.exist
    expect(result?.result?.outputs.log).to.equal("ok")
    expect(result!.result!.detail?.namespaceStatus).to.exist
  })
})
