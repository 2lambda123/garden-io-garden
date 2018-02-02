import { Environment } from "../../types/common"
import { Module } from "../../types/module"
import { Service } from "../../types/service"
import { GenericModuleHandler } from "../../moduleHandlers/generic"
import { ConfigurationError } from "../../exceptions"
import { Memoize } from "typescript-memoize"
import { GCloud } from "./gcloud"
import { values } from "lodash"

export const GOOGLE_CLOUD_DEFAULT_REGION = "us-central1"

export abstract class GoogleCloudProviderBase<T extends Module> extends GenericModuleHandler<T> {
  abstract name: string
  abstract supportedModuleTypes: string[]

  async getEnvironmentStatus() {
    let sdkInfo

    const output = {
      configured: true,
      detail: {
        sdkInstalled: true,
        sdkInitialized: true,
        betaComponentsInstalled: true,
        sdkInfo: {},
      },
    }

    try {
      sdkInfo = output.detail.sdkInfo = await this.gcloud().json(["info"])
    } catch (err) {
      output.configured = false
      output.detail.sdkInstalled = false
    }

    if (!sdkInfo.config.account) {
      output.configured = false
      output.detail.sdkInitialized = false
    }

    if (!sdkInfo.installation.components.beta) {
      output.configured = false
      output.detail.betaComponentsInstalled = false
    }

    return output
  }

  async configureEnvironment() {
    const status = await this.getEnvironmentStatus()

    if (!status.detail.sdkInstalled) {
      throw new ConfigurationError(
        "Google Cloud SDK is not installed. " +
        "Please visit https://cloud.google.com/sdk/downloads for installation instructions.",
        {},
      )
    }

    if (!status.detail.betaComponentsInstalled) {
      this.context.log.info("google-cloud-functions", `Installing gcloud SDK beta components...`)
      await this.gcloud().call(["components update"])
      await this.gcloud().call(["components install beta"])
    }

    if (!status.detail.sdkInitialized) {
      this.context.log.info("google-cloud-functions", `Initializing SDK...`)
      await this.gcloud().tty(["init"], { silent: false })
    }
  }

  @Memoize()
  protected gcloud(project?: string, account?: string) {
    return new GCloud({ project, account })
  }

  protected getProject(service: Service<T>, env: Environment) {
    // TODO: this is very contrived - we should rethink this a bit and pass
    // provider configuration when calling the plugin
    const providerConfig = values(env.config.providers).filter(p => p.type === this.name)[0]
    return providerConfig["default-project"] || service.config.project || null
  }
}
