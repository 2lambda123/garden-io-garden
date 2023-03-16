/*
 * Copyright (C) 2018-2022 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { expect } from "chai"

import { TestGarden, expectError } from "../../../../../helpers"
import { ConfigGraph } from "../../../../../../src/graph/config-graph"
import { getKubernetesTestGarden } from "./common"
import { RunTask } from "../../../../../../src/tasks/run"
import { emptyDir, pathExists } from "fs-extra"
import { join } from "path"
import { clearRunResult } from "../../../../../../src/plugins/kubernetes/run-results"
import { KubernetesPodRunAction } from "../../../../../../src/plugins/kubernetes/kubernetes-type/kubernetes-pod"

describe("kubernetes-type pod Run", () => {
  let garden: TestGarden
  let graph: ConfigGraph

  before(async () => {
    garden = await getKubernetesTestGarden()
  })

  beforeEach(async () => {
    graph = await garden.getConfigGraph({ log: garden.log, emit: false })
  })

  it("should run a basic Run and store its result", async () => {
    const action = graph.getRun("echo-task")

    const testTask = new RunTask({
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

    // Verify that the result was saved
    const actions = await garden.getActionRouter()
    const storedResult = await actions.run.getResult({
      log: garden.log,
      action: await garden.resolveAction<KubernetesPodRunAction>({ action, log: garden.log, graph }),
      graph,
    })

    expect(storedResult).to.exist
  })

  it("should not store Run results if cacheResult=false", async () => {
    const action = graph.getRun("echo-task")
    action.getConfig().spec.cacheResult = false

    const testTask = new RunTask({
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

    await garden.processTasks({ tasks: [testTask], throwOnError: true })

    // Verify that the result was saved
    const actions = await garden.getActionRouter()
    const storedResult = await actions.run.getResult({
      log: garden.log,
      action: await garden.resolveAction<KubernetesPodRunAction>({ action, log: garden.log, graph }),
      graph,
    })

    expect(storedResult.state).to.eql("not-ready")
  })

  it("should run a task in a different namespace, if configured", async () => {
    const action = graph.getRun("with-namespace-task")

    const testTask = new RunTask({
      garden,
      graph,
      action,
      log: garden.log,
      force: true,
      forceBuild: false,
    })

    const results = await garden.processTasks({ tasks: [testTask], throwOnError: true })
    const result = results.results.getResult(testTask)

    expect(result).to.exist
    expect(result!.result).to.exist
    expect(result?.result?.outputs.log).to.equal(action.getConfig().spec.namespace)
  })

  // TODO-G2: solver gets stuck in an infinite loop
  it.skip("should fail if an error occurs, but store the result", async () => {
    const action = graph.getRun("echo-task")
    action.getConfig().spec.command = ["bork"] // this will fail

    const testTask = new RunTask({
      garden,
      graph,
      action,
      log: garden.log,
      force: true,
      forceBuild: false,
    })

    await expectError(
      async () => await garden.processTasks({ tasks: [testTask], throwOnError: true }),
      (err) => expect(err.message).to.match(/bork/)
    )

    const actions = await garden.getActionRouter()

    // We also verify that, despite the task failing, its result was still saved.
    const result = await actions.run.getResult({
      log: garden.log,
      action: await garden.resolveAction<KubernetesPodRunAction>({ action, log: garden.log, graph }),
      graph,
    })

    expect(result).to.exist
  })

  context("artifacts are specified", () => {
    it("should copy artifacts out of the container", async () => {
      const action = graph.getRun("artifacts-task")

      const testTask = new RunTask({
        garden,
        graph,
        action,
        log: garden.log,
        force: true,
        forceBuild: false,
      })

      await emptyDir(garden.artifactsPath)

      await garden.processTasks({ tasks: [testTask], throwOnError: true })

      expect(await pathExists(join(garden.artifactsPath, "task.txt"))).to.be.true
      expect(await pathExists(join(garden.artifactsPath, "subdir", "task.txt"))).to.be.true
    })

    it("should fail if an error occurs, but copy the artifacts out of the container", async () => {
      const action = graph.getRun("artifacts-task-fail")

      const testTask = new RunTask({
        garden,
        graph,
        action,
        log: garden.log,
        force: true,
        forceBuild: false,
      })
      await emptyDir(garden.artifactsPath)

      const results = await garden.processTasks({ tasks: [testTask], throwOnError: false })

      expect(results.error).to.exist

      expect(await pathExists(join(garden.artifactsPath, "test.txt"))).to.be.true
      expect(await pathExists(join(garden.artifactsPath, "subdir", "test.txt"))).to.be.true
    })

    it("should handle globs when copying artifacts out of the container", async () => {
      const action = graph.getRun("globs-task")

      const testTask = new RunTask({
        garden,
        graph,
        action,
        log: garden.log,
        force: true,
        forceBuild: false,
      })

      await emptyDir(garden.artifactsPath)

      await garden.processTasks({ tasks: [testTask], throwOnError: true })

      expect(await pathExists(join(garden.artifactsPath, "subdir", "task.txt"))).to.be.true
      expect(await pathExists(join(garden.artifactsPath, "output.txt"))).to.be.true
    })
  })
})
