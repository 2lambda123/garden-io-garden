import * as Joi from "joi"
import { Task } from "../task-graph"
import { GardenContext } from "../context"
import { BuildTask } from "./build"
import { values } from "lodash"
import { Service } from "../types/service"
import { JoiPrimitive } from "../types/common"

export class DeployTask extends Task {
  type = "deploy"

  constructor(
    private ctx: GardenContext,
    private service: Service<any>,
    private force: boolean,
    private forceBuild: boolean) {
    super()
  }

  async getDependencies() {
    const serviceDeps = this.service.module.config.services[this.service.name].dependencies
    const services = await this.ctx.getServices(serviceDeps)
    const deps: Task[] = values(services).map((s) => {
      return new DeployTask(this.ctx, s, this.force, this.forceBuild)
    })

    deps.push(new BuildTask(this.service.module, this.forceBuild))
    return deps
  }

  getKey() {
    // TODO: Include version in the task key (may need to make this method async).
    return this.service.name
  }

  async process() {
    // TODO: get version from build task results
    const version = await this.service.module.getVersion()
    const status = await this.ctx.getServiceStatus(this.service)

    if (
      !this.force &&
      version === status.version &&
      status.state === "ready"
    ) {
      // already deployed and ready
      this.ctx.log.verbose({
        section: this.service.name,
        msg: `Version ${version} already deployed`,
      })
      return status
    }

    const serviceContext = { envVars: await this.prepareEnvVars(version) }

    return this.ctx.deployService(this.service, serviceContext)
  }

  private async prepareEnvVars(version: string) {
    const envVars = {
      GARDEN_VERSION: version,
    }
    const dependencies = await this.service.getDependencies(this.ctx)

    for (const key in this.ctx.config.variables) {
      envVars[key] = this.ctx.config.variables[key]
    }

    for (const dep of dependencies) {
      const outputs = await this.ctx.getServiceOutputs(dep)
      const serviceEnvName = dep.getEnvVarName()

      for (const key of Object.keys(outputs)) {
        const envKey = Joi.attempt(key, Joi.string())
        const envVarName = `GARDEN_SERVICES_${serviceEnvName}_${envKey}`.toUpperCase()
        envVars[envVarName] = Joi.attempt(outputs[key], JoiPrimitive())
      }
    }

    return envVars
  }
}
