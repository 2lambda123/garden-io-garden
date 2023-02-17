/*
 * Copyright (C) 2018-2022 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import tmp from "tmp-promise"
import { ProjectConfig } from "../../../../../../src/config/project"
import execa = require("execa")
import { DEFAULT_API_VERSION } from "../../../../../../src/constants"
import { expect } from "chai"
import { TestGarden, makeTempDir, createProjectConfig } from "../../../../../helpers"
import { DeployTask } from "../../../../../../src/tasks/deploy"
import { isSubset } from "../../../../../../src/util/is-subset"

describe("persistentvolumeclaim", () => {
  let tmpDir: tmp.DirectoryResult
  let projectConfigFoo: ProjectConfig

  before(async () => {
    tmpDir = await makeTempDir()

    await execa("git", ["init", "--initial-branch=main"], { cwd: tmpDir.path })

    projectConfigFoo = createProjectConfig({
      path: tmpDir.path,
      providers: [{ name: "local-kubernetes", namespace: "default" }],
    })
  })

  after(async () => {
    await tmpDir.cleanup()
  })

  it("should successfully deploy a simple PVC", async () => {
    const garden = await TestGarden.factory(tmpDir.path, {
      plugins: [],
      config: projectConfigFoo,
    })

    const spec = {
      accessModes: ["ReadWriteOnce"],
      resources: {
        requests: {
          storage: "1Gi",
        },
      },
    }

    garden.setModuleConfigs([
      {
        apiVersion: DEFAULT_API_VERSION,
        name: "test",
        type: "persistentvolumeclaim",
        allowPublish: false,
        build: { dependencies: [] },
        disabled: false,
        path: tmpDir.path,
        serviceConfigs: [],
        taskConfigs: [],
        testConfigs: [],
        spec: {
          spec,
        },
      },
    ])

    const graph = await garden.getConfigGraph({ log: garden.log, emit: false })
    const action = await garden.resolveAction({ action: graph.getDeploy("test"), log: garden.log })

    const deployTask = new DeployTask({
      garden,
      graph,
      log: garden.log,
      action,
      force: true,
      forceBuild: false,
      syncModeDeployNames: [],
      localModeDeployNames: [],
    })

    await garden.processTasks({ tasks: [deployTask], throwOnError: true })

    const actions = await garden.getActionRouter()
    const status = await actions.getDeployStatuses({
      log: garden.log,
      graph,
    })

    const remoteResources = status.detail["remoteResources"]

    expect(status.state.state === "ready")
    expect(remoteResources.length).to.equal(1)
    expect(
      isSubset(remoteResources[0], {
        apiVersion: "v1",
        kind: "PersistentVolumeClaim",
        metadata: { name: "test", namespace: "default" },
        spec,
      })
    ).to.be.true

    await actions.deploy.delete({ log: garden.log, action, graph })
  })
})
