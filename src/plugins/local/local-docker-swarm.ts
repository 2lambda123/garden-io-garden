import * as Docker from "dockerode"
import { exec } from "child-process-promise"
import { Memoize } from "typescript-memoize"
import { DeploymentError } from "../../exceptions"
import {
  DeployServiceParams, ExecInServiceParams, GetServiceOutputsParams, GetServiceStatusParams,
  Plugin,
} from "../../types/plugin"
import { ContainerModule } from "../container"
import { sortBy, map } from "lodash"
import { sleep } from "../../util"
import { Module } from "../../types/module"
import { ServiceState, ServiceStatus } from "../../types/service"

// should this be configurable and/or global across providers?
const DEPLOY_TIMEOUT = 30

// TODO: Support namespacing
export class LocalDockerSwarmBase<T extends Module> extends Plugin<T> {
  name = "local-docker-swarm"
  supportedModuleTypes = ["container"]

  @Memoize()
  protected getDocker() {
    return new Docker()
  }

  async getEnvironmentStatus() {
    const docker = this.getDocker()

    try {
      await docker.swarmInspect()

      return {
        configured: true,
      }
    } catch (err) {
      if (err.statusCode === 503) {
        // swarm has not been initialized
        return {
          configured: false,
          services: [],
        }
      } else {
        throw err
      }
    }
  }

  async getServiceStatus({ service }: GetServiceStatusParams<ContainerModule>): Promise<ServiceStatus> {
    const docker = this.getDocker()
    const swarmServiceName = this.getSwarmServiceName(service.name)
    const swarmService = docker.getService(swarmServiceName)

    let swarmServiceStatus

    try {
      swarmServiceStatus = await swarmService.inspect()
    } catch (err) {
      if (err.statusCode === 404) {
        // service does not exist
        return {}
      } else {
        throw err
      }
    }

    const image = swarmServiceStatus.Spec.TaskTemplate.ContainerSpec.Image
    const version = image.split(":")[1]

    const { lastState, lastError } = await this.getServiceState(swarmServiceStatus.ID)

    return {
      providerId: swarmServiceStatus.ID,
      version,
      runningReplicas: swarmServiceStatus.Spec.Mode.Replicated.Replicas,
      state: mapContainerState(lastState),
      lastError: lastError || undefined,
      createdAt: swarmServiceStatus.CreatedAt,
      updatedAt: swarmServiceStatus.UpdatedAt,
    }
  }

  async configureEnvironment() {
    const status = await this.getEnvironmentStatus()

    if (!status.configured) {
      await this.getDocker().swarmInit({})
    }
  }

  async deployService({ context, service, serviceContext, env }: DeployServiceParams<ContainerModule>) {
    // TODO: split this method up and test
    const version = await service.module.getVersion()

    this.context.log.info({ section: service.name, msg: `Deploying version ${version}` })

    const identifier = await service.module.getImageId()
    const ports = service.config.ports.map(p => {
      const port: any = {
        Protocol: p.protocol ? p.protocol.toLowerCase() : "tcp",
        TargetPort: p.container,
      }

      if (p.hostPort) {
        port.PublishedPort = p.hostPort
      }
    })

    const envVars = map(serviceContext.envVars, (v, k) => `${k}=${v}`)

    const volumeMounts = service.config.volumes.map(v => {
      // TODO-LOW: Support named volumes
      if (v.hostPath) {
        return {
          Type: "bind",
          Source: v.hostPath,
          Target: v.containerPath,
        }
      } else {
        return {
          Type: "tmpfs",
          Target: v.containerPath,
        }
      }
    })

    const opts: any = {
      Name: this.getSwarmServiceName(service.name),
      Labels: {
        environment: env.name,
        namespace: env.namespace,
        provider: this.name,
      },
      TaskTemplate: {
        ContainerSpec: {
          Image: identifier,
          Command: service.config.command,
          Env: envVars,
          Mounts: volumeMounts,
        },
        Resources: {
          Limits: {},
          Reservations: {},
        },
        RestartPolicy: {},
        Placement: {},
      },
      Mode: {
        Replicated: {
          Replicas: 1,
        },
      },
      UpdateConfig: {
        Parallelism: 1,
      },
      EndpointSpec: {
        Ports: ports,
      },
    }

    const docker = this.getDocker()
    const serviceStatus = await this.getServiceStatus({ context, service, env })
    let swarmServiceStatus
    let serviceId

    if (serviceStatus.providerId) {
      const swarmService = await docker.getService(serviceStatus.providerId)
      swarmServiceStatus = await swarmService.inspect()
      opts.version = parseInt(swarmServiceStatus.Version.Index, 10)
      this.context.log.verbose({
        section: service.name,
        msg: `Updating existing Swarm service (version ${opts.version})`,
      })
      await swarmService.update(opts)
      serviceId = serviceStatus.providerId
    } else {
      this.context.log.verbose({
        section: service.name,
        msg: `Creating new Swarm service`,
      })
      const swarmService = await docker.createService(opts)
      serviceId = swarmService.ID
    }

    // Wait for service to be ready
    const start = new Date().getTime()

    while (true) {
      await sleep(1000)

      const { lastState, lastError } = await this.getServiceState(serviceId)

      if (lastError) {
        throw new DeploymentError(`Service ${service.name} ${lastState}: ${lastError}`, {
          service,
          state: lastState,
          error: lastError,
        })
      }

      if (mapContainerState(lastState) === "ready") {
        break
      }

      if (new Date().getTime() - start > DEPLOY_TIMEOUT * 1000) {
        throw new DeploymentError(`Timed out deploying ${service.name} (status: ${lastState}`, {
          service,
          state: lastState,
        })
      }
    }

    this.context.log.info({
      section: service.name,
      msg: `Ready`,
    })

    return this.getServiceStatus({ context, service, env })
  }

  async getServiceOutputs({ service }: GetServiceOutputsParams<ContainerModule>) {
    return {
      host: this.getSwarmServiceName(service.name),
    }
  }

  async execInService({ context, env, service, command }: ExecInServiceParams<ContainerModule>) {
    const status = await this.getServiceStatus({ context, service, env })

    if (!status.state || status.state !== "ready") {
      throw new DeploymentError(`Service ${service.name} is not running`, {
        name: service.name,
        state: status.state,
      })
    }

    // This is ugly, but dockerode doesn't have this, or at least it's too cumbersome to implement.
    const swarmServiceName = this.getSwarmServiceName(service.name)
    const servicePsCommand = [
      "docker", "service", "ps",
      "-f", `'name=${swarmServiceName}.1'`,
      "-f", `'desired-state=running'`,
      swarmServiceName,
      "-q",
    ]
    let res = await exec(servicePsCommand.join(" "))
    const serviceContainerId = `${swarmServiceName}.1.${res.stdout.trim()}`

    const execCommand = ["docker", "exec", serviceContainerId, ...command]
    res = await exec(execCommand.join(" "))

    return { code: 0, output: "", stdout: res.stdout, stderr: res.stderr }
  }

  private getSwarmServiceName(serviceName: string) {
    return `${this.context.projectName}--${serviceName}`
  }

  private async getServiceTask(serviceId: string) {
    let tasks = await this.getDocker().listTasks({
      // Service: this.getSwarmServiceName(service.name),
    })
    // For whatever (presumably totally reasonable) reason, the filter option above does not work.
    tasks = tasks.filter(t => t.ServiceID === serviceId)
    tasks = sortBy(tasks, ["CreatedAt"]).reverse()

    return tasks[0]
  }

  private async getServiceState(serviceId: string) {
    const task = await this.getServiceTask(serviceId)

    let lastState
    let lastError

    if (task) {
      lastState = task.Status.State
      lastError = task.Status.Err || null
    }

    return { lastState, lastError }
  }
}

export class LocalDockerSwarmProvider extends LocalDockerSwarmBase<ContainerModule> { }

// see schema in https://docs.docker.com/engine/api/v1.35/#operation/TaskList
const taskStateMap: { [key: string]: ServiceState } = {
  new: "deploying",
  allocated: "deploying",
  pending: "deploying",
  assigned: "deploying",
  accepted: "deploying",
  preparing: "deploying",
  starting: "deploying",
  running: "ready",
  ready: "ready",
  complete: "stopped",
  shutdown: "stopped",
  failed: "unhealthy",
  rejected: "unhealthy",
}

function mapContainerState(lastState: string | undefined): ServiceState | undefined {
  return lastState ? taskStateMap[lastState] : undefined
}
