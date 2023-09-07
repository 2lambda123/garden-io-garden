---
title: Ephemeral Kubernetes Clusters
order: 4
---

# Ephemeral Kubernetes Clusters

At Garden, we're committed to reducing the friction in onboarding and trying out our platform for your own projects. To make Kubernetes adoption more accessible and convenient, we introduce **Ephemeral Kubernetes Clusters**. These clusters are designed to provide you with a hassle-free way to explore Garden.io's capabilities and Kubernetes without the need of an existing Kubernetes cluster.

## Configuring your projects to use ephemeral Kubernetes cluster

To get started with Ephemeral Kubernetes Clusters, follow these steps:

1. Login to Garden Cloud using `garden login` from your project root.
2. Configure the `ephemeral-kubernetes` provider in your project's configuration file. Here's an example configuration:

```yaml
providers:
  - name: ephemeral-kubernetes
    environments: [remote]

```
In the above configuration, we configure ephemeral-kubernetes for the `remote` environment.

## Deploy your project on ephemeral cluster

With the ephemeral-kubernetes provider configured, you can now deploy your project using the Garden CLI. Simply run the following command:

```
garden deploy --env remote
```

The CLI will automatically provision an ephemeral Kubernetes cluster for your project and deploy your application to it.

### Usage quota and managing clusters

The ephemeral Kubernetes clusters are provided for free to all users. The ephemeral clusters are designed for short-term use and allow you to run and test your applications on Kubernetes.

Each user is granted a maximum of **20 hours per month** of ephemeral cluster usage where each cluster has a maximum lifetime of **4 hours**. After this period, the cluster is automatically destroyed.

If you need to destroy the cluster before its maximum lifetime of 4 hours expires, you can do so by visiting [Garden Cloud](https://app.garden.io) and selecting the option to destroy the ephemeral cluster from there. This allows you to release resources and terminate the cluster when it's no longer needed.

## Ingresses

Ephemeral Kubernetes Clusters fully support ingresses and each cluster is assigned its own unique default hostname dynamically when created.

The ingress URLs are not publicly accessible and require authentication via GitHub. To preview an ingress URL, you must authenticate with GitHub and authorize the "Garden Ephemeral Environment Previews" app.


Note: Ingress URLs can only be previewed by the user who was logged in to Garden Cloud when a deployment was done using the ephemeral-kubernetes provider.

### Referring to the dynamic hostname in your Garden configs

If you want to refer to the hostname that is assigned dynamically when the cluster is created, you can refer to that using the output `${providers.ephemeral-kubernetes.outputs.default-hostname}`. This can be useful if, for example, you want to expose an ingress on a subdomain of the default hostname. e.g. You want to expose api on api.<default-hostname>.

To leverage the dynamically assigned hostname when your ephemeral cluster is created, you can reference it using the following output syntax: `${providers.ephemeral-kubernetes.outputs.default-hostname}`. This proves particularly valuable when you need to expose an ingress on a subdomain of the default hostname.

For instance, if you wish to expose an API service on a subdomain like api.<default-hostname>, you can easily achieve this in your Garden configuration. Here's an example of how to configure your Garden file to expose an API on a subdomain of the default hostname:

```
....
ingresses:
    - path: /
      port: http
      hostname: api.${providers.ephemeral-kubernetes.outputs.default-hostname}
```

## Accessing the Ephemeral Cluster via Kubeconfig

Once your ephemeral cluster is created, the Kubeconfig file for that cluster is stored on your local computer. The path to the Kubeconfig file is shown in the logs when you deploy your project using Garden and looks like following:
```
Kubeconfig for ephemeral cluster saved at path: /garden/examples/ephemeral-cluster-demo/.garden/ephemeral-kubernetes/<cluster-id>-kubeconfig.yaml
```

This Kubeconfig file allows you to interact with the cluster using kubectl or other Kubernetes tools.