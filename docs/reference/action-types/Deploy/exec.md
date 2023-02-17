---
title: "`exec` Deploy"
tocTitle: "`exec` Deploy"
---

# `exec` Deploy

## Description

Run and manage a persistent process or service with shell commands.

Below is the full schema reference for the action. For an introduction to configuring Garden, please look at our [Configuration
guide](../../../using-garden/configuration-overview.md).

The [first section](#complete-yaml-schema) contains the complete YAML schema, and the [second section](#configuration-keys) describes each schema key.

`exec` actions also export values that are available in template strings. See the [Outputs](#outputs) section below for details.

## Complete YAML Schema

The values in the schema below are the default values.

```yaml
# The schema version of this config (currently not used).
apiVersion: garden.io/v0

# The kind of action you want to define (one of Build, Deploy, Run or Test).
kind:

# The type of action, e.g. `exec`, `container` or `kubernetes`. Some are built into Garden but mostly these will be
# defined by your configured providers.
type:

# A valid name for the action. Must be unique across all actions of the same _kind_ in your project.
name:

# A description of the action.
description:

# By default, the directory where the action is defined is used as the source for the build context.
#
# You can override this by setting either `source.path` to another (POSIX-style) path relative to the action source
# directory, or `source.repository` to get the source from an external repository.
#
# If using `source.path`, you must make sure the target path is in a git repository.
#
# For `source.repository` behavior, please refer to the [Remote Sources
# guide](https://docs.garden.io/advanced/using-remote-sources).
source:
  # A relative POSIX-style path to the source directory for this action. You must make sure this path exists and is
  # ina git repository!
  path:

  # When set, Garden will import the action source from this repository, but use this action configuration (and not
  # scan for configs in the separate repository).
  repository:
    # A remote repository URL. Currently only supports git servers. Must contain a hash suffix pointing to a specific
    # branch or tag, with the format: <git remote url>#<branch|tag>
    url:

# A list of other actions that this action depends on, and should be built, deployed or run (depending on the action
# type) before processing this action.
#
# Each dependency should generally be expressed as a `"<kind>.<name>"` string, where _<kind>_ is one of `build`,
# `deploy`, `run` or `test`, and _<name>_ is the name of the action to depend on.
#
# You may also optionally specify a dependency as an object, e.g. `{ kind: "Build", name: "some-image" }`.
#
# Any empty values (i.e. null or empty strings) are ignored, so that you can conditionally add in a dependency via
# template expressions.
dependencies: []

# Set this to `true` to disable the action. You can use this with conditional template strings to disable actions
# based on, for example, the current environment or other variables (e.g. `disabled: ${environment.name == "prod"}`).
# This can be handy when you only need certain actions for specific environments, e.g. only for development.
#
# For Build actions, this means the build is not performed _unless_ it is declared as a dependency by another enabled
# action (in which case the Build is assumed to be necessary for the dependant action to be run or built).
#
# For other action kinds, the action is skipped in all scenarios, and dependency declarations to it are ignored. Note
# however that template strings referencing outputs (i.e. runtime outputs) will fail to resolve when the action is
# disabled, so you need to make sure to provide alternate values for those if you're using them, using conditional
# expressions.
disabled: false

# Specify a list of POSIX-style paths or globs that should be regarded as source files for this action, and thus will
# affect the computed _version_ of the action.
#
# For actions other than _Build_ actions, this is usually not necessary to specify, or is implicitly inferred. An
# exception would be e.g. an `exec` action without a `build` reference, where the relevant files cannot be inferred
# and you want to define which files should affect the version of the action, e.g. to make sure a Test action is run
# when certain files are modified.
#
# _Build_ actions have a different behavior, since they generally are based on some files in the source tree, so
# please reference the docs for more information on those.
#
# Note that you can also _exclude_ files using the `exclude` field or by placing `.gardenignore` files in your source
# tree, which use the same format as `.gitignore` files. See the [Configuration Files
# guide](https://docs.garden.io/using-garden/configuration-overview#including-excluding-files-and-directories) for
# details.
include:

# Specify a list of POSIX-style paths or glob patterns that should be explicitly excluded from the action's version.
#
# For actions other than _Build_ actions, this is usually not necessary to specify, or is implicitly inferred. For
# _Deploy_, _Run_ and _Test_ actions, the exclusions specified here only applied on top of explicitly set `include`
# paths, or such paths inferred by providers. See the [Configuration Files
# guide](https://docs.garden.io/using-garden/configuration-overview#including-excluding-files-and-directories) for
# details.
#
# Unlike the `scan.exclude` field in the project config, the filters here have _no effect_ on which files and
# directories are watched for changes when watching is enabled. Use the project `scan.exclude` field to affect those,
# if you have large directories that should not be watched for changes.
exclude:

# A map of variables scoped to this particular action. These are resolved before any other parts of the action
# configuration and take precedence over group-scoped variables (if applicable) and project-scoped variables, in that
# order. They may reference group-scoped and project-scoped variables, and generally can use any template strings
# normally allowed when resolving the action.
variables:

# Specify a list of paths (relative to the directory where the action is defined) to a file containing variables, that
# we apply on top of the action-level `variables` field, and take precedence over group-level variables (if
# applicable) and project-level variables, in that order.
#
# If you specify multiple paths, they are merged in the order specified, i.e. the last one takes precedence over the
# previous ones.
#
# The format of the files is determined by the configured file's extension:
#
# * `.env` - Standard "dotenv" format, as defined by [dotenv](https://github.com/motdotla/dotenv#rules).
# * `.yaml`/`.yml` - YAML. The file must consist of a YAML document, which must be a map (dictionary). Keys may
# contain any value type.
# * `.json` - JSON. Must contain a single JSON _object_ (not an array).
#
# _NOTE: The default varfile format will change to YAML in Garden v0.13, since YAML allows for definition of nested
# objects and arrays._
#
# To use different varfiles in different environments, you can template in the environment name to the varfile name,
# e.g. `varfile: "my-action.\$\{environment.name\}.env` (this assumes that the corresponding varfiles exist).
#
# If a listed varfile cannot be found, it is ignored.
varfiles: []

# Specify a _Build_ action, and resolve this action from the context of that Build.
#
# For example, you might create an `exec` Build which prepares some manifests, and then reference that in a
# `kubernetes` _Deploy_ action, and the resulting manifests from the Build.
#
# This would mean that instead of looking for manifest files relative to this action's location in your project
# structure, the output directory for the referenced `exec` Build would be the source.
build:

spec:
  # If `true`, runs file inside of a shell. Uses `/bin/sh` on UNIX and `cmd.exe` on Windows. A different shell can be
  # specified as a string. The shell should understand the `-c` switch on UNIX or `/d /s /c` on Windows.
  #
  # Note that if this is not set, no shell interpreter (Bash, `cmd.exe`, etc.) is used, so shell features such as
  # variables substitution (`echo $PATH`) are not allowed.
  #
  # We recommend against using this option since it is:
  #
  # - not cross-platform, encouraging shell-specific syntax.
  # - slower, because of the additional shell interpretation.
  # - unsafe, potentially allowing command injection.
  shell:

  # The command to run to perform the deployment.
  #
  # Note that if a Build is referenced in the `build` field, the command will be run from the build directory for that
  # Build action. If that Build has `buildAtSource: true` set, the command will be run from the source directory of
  # the Build action. If no `build` reference is set, the command is run from the source directory of this action.
  deployCommand:

  # Optionally set a command to check the status of the deployment. If this is specified, it is run before the
  # `deployCommand`. If the command runs successfully and returns exit code of 0, the deployment is considered already
  # deployed and the `deployCommand` is not run.
  #
  # If this is not specified, the deployment is always reported as "unknown", so it's highly recommended to specify
  # this command if possible.
  #
  # Note that if a Build is referenced in the `build` field, the command will be run from the build directory for that
  # Build action. If that Build has `buildAtSource: true` set, the command will be run from the source directory of
  # the Build action. If no `build` reference is set, the command is run from the source directory of this action.
  statusCommand:

  # Optionally set a command to clean the deployment up, e.g. when running `garden delete env`.
  #
  # Note that if a Build is referenced in the `build` field, the command will be run from the build directory for that
  # Build action. If that Build has `buildAtSource: true` set, the command will be run from the source directory of
  # the Build action. If no `build` reference is set, the command is run from the source directory of this action.
  cleanupCommand:

  # The maximum duration (in seconds) to wait for a local script to exit.
  timeout:

  # Environment variables to set when running the deploy and status commands.
  env: {}

  syncMode:
    # The command to run to deploy in sync mode. When deploying in sync mode, Garden assumes that the command starts a
    # persistent process and does not wait for it return. The logs from the process can be retrieved via the `garden
    # logs` command as usual.
    #
    # If a `statusCommand` is set, Garden will wait until it returns a zero exit code before considering the
    # deployment ready. Otherwise it considers it immediately ready.
    #
    # Note that if a Build is referenced in the `build` field, the command will be run from the build directory for
    # that Build action. If that Build has `buildAtSource: true` set, the command will be run from the source
    # directory of the Build action. If no `build` reference is set, the command is run from the source directory of
    # this action.
    command:

    # Optionally set a command to check the status of the deployment in sync mode. Garden will run the status command
    # at an interval until it returns a zero exit code or times out.
    #
    # If no `statusCommand` is set, Garden will consider the deploy ready as soon as it has started the process.
    #
    # Note that if a Build is referenced in the `build` field, the command will be run from the build directory for
    # that Build action. If that Build has `buildAtSource: true` set, the command will be run from the source
    # directory of the Build action. If no `build` reference is set, the command is run from the source directory of
    # this action.
    statusCommand:

    # The maximum duration (in seconds) to wait for a for the `statusCommand` to return a zero exit code. Ignored if
    # no `statusCommand` is set.
    timeout: 10
```

## Configuration Keys

### `apiVersion`

The schema version of this config (currently not used).

| Type     | Allowed Values | Default          | Required |
| -------- | -------------- | ---------------- | -------- |
| `string` | "garden.io/v0" | `"garden.io/v0"` | Yes      |

### `kind`

The kind of action you want to define (one of Build, Deploy, Run or Test).

| Type     | Required |
| -------- | -------- |
| `string` | Yes      |

### `type`

The type of action, e.g. `exec`, `container` or `kubernetes`. Some are built into Garden but mostly these will be defined by your configured providers.

| Type     | Required |
| -------- | -------- |
| `string` | Yes      |

### `name`

A valid name for the action. Must be unique across all actions of the same _kind_ in your project.

| Type     | Required |
| -------- | -------- |
| `string` | Yes      |

### `description`

A description of the action.

| Type     | Required |
| -------- | -------- |
| `string` | No       |

### `source`

By default, the directory where the action is defined is used as the source for the build context.

You can override this by setting either `source.path` to another (POSIX-style) path relative to the action source directory, or `source.repository` to get the source from an external repository.

If using `source.path`, you must make sure the target path is in a git repository.

For `source.repository` behavior, please refer to the [Remote Sources guide](https://docs.garden.io/advanced/using-remote-sources).

| Type     | Required |
| -------- | -------- |
| `object` | No       |

### `source.path`

[source](#source) > path

A relative POSIX-style path to the source directory for this action. You must make sure this path exists and is ina git repository!

| Type        | Required |
| ----------- | -------- |
| `posixPath` | No       |

### `source.repository`

[source](#source) > repository

When set, Garden will import the action source from this repository, but use this action configuration (and not scan for configs in the separate repository).

| Type     | Required |
| -------- | -------- |
| `object` | No       |

### `source.repository.url`

[source](#source) > [repository](#sourcerepository) > url

A remote repository URL. Currently only supports git servers. Must contain a hash suffix pointing to a specific branch or tag, with the format: <git remote url>#<branch|tag>

| Type               | Required |
| ------------------ | -------- |
| `gitUrl \| string` | Yes      |

Example:

```yaml
source:
  ...
  repository:
    ...
    url: "git+https://github.com/org/repo.git#v2.0"
```

### `dependencies[]`

A list of other actions that this action depends on, and should be built, deployed or run (depending on the action type) before processing this action.

Each dependency should generally be expressed as a `"<kind>.<name>"` string, where _<kind>_ is one of `build`, `deploy`, `run` or `test`, and _<name>_ is the name of the action to depend on.

You may also optionally specify a dependency as an object, e.g. `{ kind: "Build", name: "some-image" }`.

Any empty values (i.e. null or empty strings) are ignored, so that you can conditionally add in a dependency via template expressions.

| Type                     | Default | Required |
| ------------------------ | ------- | -------- |
| `array[actionReference]` | `[]`    | No       |

Example:

```yaml
dependencies:
  - build.my-image
  - deploy.api
```

### `disabled`

Set this to `true` to disable the action. You can use this with conditional template strings to disable actions based on, for example, the current environment or other variables (e.g. `disabled: ${environment.name == "prod"}`). This can be handy when you only need certain actions for specific environments, e.g. only for development.

For Build actions, this means the build is not performed _unless_ it is declared as a dependency by another enabled action (in which case the Build is assumed to be necessary for the dependant action to be run or built).

For other action kinds, the action is skipped in all scenarios, and dependency declarations to it are ignored. Note however that template strings referencing outputs (i.e. runtime outputs) will fail to resolve when the action is disabled, so you need to make sure to provide alternate values for those if you're using them, using conditional expressions.

| Type      | Default | Required |
| --------- | ------- | -------- |
| `boolean` | `false` | No       |

### `include[]`

Specify a list of POSIX-style paths or globs that should be regarded as source files for this action, and thus will affect the computed _version_ of the action.

For actions other than _Build_ actions, this is usually not necessary to specify, or is implicitly inferred. An exception would be e.g. an `exec` action without a `build` reference, where the relevant files cannot be inferred and you want to define which files should affect the version of the action, e.g. to make sure a Test action is run when certain files are modified.

_Build_ actions have a different behavior, since they generally are based on some files in the source tree, so please reference the docs for more information on those.

Note that you can also _exclude_ files using the `exclude` field or by placing `.gardenignore` files in your source tree, which use the same format as `.gitignore` files. See the [Configuration Files guide](https://docs.garden.io/using-garden/configuration-overview#including-excluding-files-and-directories) for details.

| Type               | Required |
| ------------------ | -------- |
| `array[posixPath]` | No       |

Example:

```yaml
include:
  - my-app.js
  - some-assets/**/*
```

### `exclude[]`

Specify a list of POSIX-style paths or glob patterns that should be explicitly excluded from the action's version.

For actions other than _Build_ actions, this is usually not necessary to specify, or is implicitly inferred. For _Deploy_, _Run_ and _Test_ actions, the exclusions specified here only applied on top of explicitly set `include` paths, or such paths inferred by providers. See the [Configuration Files guide](https://docs.garden.io/using-garden/configuration-overview#including-excluding-files-and-directories) for details.

Unlike the `scan.exclude` field in the project config, the filters here have _no effect_ on which files and directories are watched for changes when watching is enabled. Use the project `scan.exclude` field to affect those, if you have large directories that should not be watched for changes.

| Type               | Required |
| ------------------ | -------- |
| `array[posixPath]` | No       |

Example:

```yaml
exclude:
  - tmp/**/*
  - '*.log'
```

### `variables`

A map of variables scoped to this particular action. These are resolved before any other parts of the action configuration and take precedence over group-scoped variables (if applicable) and project-scoped variables, in that order. They may reference group-scoped and project-scoped variables, and generally can use any template strings normally allowed when resolving the action.

| Type     | Required |
| -------- | -------- |
| `object` | No       |

### `varfiles[]`

Specify a list of paths (relative to the directory where the action is defined) to a file containing variables, that we apply on top of the action-level `variables` field, and take precedence over group-level variables (if applicable) and project-level variables, in that order.

If you specify multiple paths, they are merged in the order specified, i.e. the last one takes precedence over the previous ones.

The format of the files is determined by the configured file's extension:

* `.env` - Standard "dotenv" format, as defined by [dotenv](https://github.com/motdotla/dotenv#rules).
* `.yaml`/`.yml` - YAML. The file must consist of a YAML document, which must be a map (dictionary). Keys may contain any value type.
* `.json` - JSON. Must contain a single JSON _object_ (not an array).

_NOTE: The default varfile format will change to YAML in Garden v0.13, since YAML allows for definition of nested objects and arrays._

To use different varfiles in different environments, you can template in the environment name to the varfile name, e.g. `varfile: "my-action.\$\{environment.name\}.env` (this assumes that the corresponding varfiles exist).

If a listed varfile cannot be found, it is ignored.

| Type               | Default | Required |
| ------------------ | ------- | -------- |
| `array[posixPath]` | `[]`    | No       |

Example:

```yaml
varfiles:
  "my-action.env"
```

### `build`

Specify a _Build_ action, and resolve this action from the context of that Build.

For example, you might create an `exec` Build which prepares some manifests, and then reference that in a `kubernetes` _Deploy_ action, and the resulting manifests from the Build.

This would mean that instead of looking for manifest files relative to this action's location in your project structure, the output directory for the referenced `exec` Build would be the source.

| Type     | Required |
| -------- | -------- |
| `string` | No       |

### `spec`

| Type     | Required |
| -------- | -------- |
| `object` | No       |

### `spec.shell`

[spec](#spec) > shell

If `true`, runs file inside of a shell. Uses `/bin/sh` on UNIX and `cmd.exe` on Windows. A different shell can be specified as a string. The shell should understand the `-c` switch on UNIX or `/d /s /c` on Windows.

Note that if this is not set, no shell interpreter (Bash, `cmd.exe`, etc.) is used, so shell features such as variables substitution (`echo $PATH`) are not allowed.

We recommend against using this option since it is:

- not cross-platform, encouraging shell-specific syntax.
- slower, because of the additional shell interpretation.
- unsafe, potentially allowing command injection.

| Type      | Required |
| --------- | -------- |
| `boolean` | No       |

### `spec.deployCommand[]`

[spec](#spec) > deployCommand

The command to run to perform the deployment.

Note that if a Build is referenced in the `build` field, the command will be run from the build directory for that Build action. If that Build has `buildAtSource: true` set, the command will be run from the source directory of the Build action. If no `build` reference is set, the command is run from the source directory of this action.

| Type            | Required |
| --------------- | -------- |
| `array[string]` | Yes      |

### `spec.statusCommand[]`

[spec](#spec) > statusCommand

Optionally set a command to check the status of the deployment. If this is specified, it is run before the `deployCommand`. If the command runs successfully and returns exit code of 0, the deployment is considered already deployed and the `deployCommand` is not run.

If this is not specified, the deployment is always reported as "unknown", so it's highly recommended to specify this command if possible.

Note that if a Build is referenced in the `build` field, the command will be run from the build directory for that Build action. If that Build has `buildAtSource: true` set, the command will be run from the source directory of the Build action. If no `build` reference is set, the command is run from the source directory of this action.

| Type            | Required |
| --------------- | -------- |
| `array[string]` | No       |

### `spec.cleanupCommand[]`

[spec](#spec) > cleanupCommand

Optionally set a command to clean the deployment up, e.g. when running `garden delete env`.

Note that if a Build is referenced in the `build` field, the command will be run from the build directory for that Build action. If that Build has `buildAtSource: true` set, the command will be run from the source directory of the Build action. If no `build` reference is set, the command is run from the source directory of this action.

| Type            | Required |
| --------------- | -------- |
| `array[string]` | No       |

### `spec.timeout`

[spec](#spec) > timeout

The maximum duration (in seconds) to wait for a local script to exit.

| Type     | Required |
| -------- | -------- |
| `number` | No       |

### `spec.env`

[spec](#spec) > env

Environment variables to set when running the deploy and status commands.

| Type     | Default | Required |
| -------- | ------- | -------- |
| `object` | `{}`    | No       |

### `spec.syncMode`

[spec](#spec) > syncMode

| Type     | Required |
| -------- | -------- |
| `object` | No       |

### `spec.syncMode.command[]`

[spec](#spec) > [syncMode](#specsyncmode) > command

The command to run to deploy in sync mode. When deploying in sync mode, Garden assumes that the command starts a persistent process and does not wait for it return. The logs from the process can be retrieved via the `garden logs` command as usual.

If a `statusCommand` is set, Garden will wait until it returns a zero exit code before considering the deployment ready. Otherwise it considers it immediately ready.

Note that if a Build is referenced in the `build` field, the command will be run from the build directory for that Build action. If that Build has `buildAtSource: true` set, the command will be run from the source directory of the Build action. If no `build` reference is set, the command is run from the source directory of this action.

| Type            | Required |
| --------------- | -------- |
| `array[string]` | No       |

### `spec.syncMode.statusCommand[]`

[spec](#spec) > [syncMode](#specsyncmode) > statusCommand

Optionally set a command to check the status of the deployment in sync mode. Garden will run the status command at an interval until it returns a zero exit code or times out.

If no `statusCommand` is set, Garden will consider the deploy ready as soon as it has started the process.

Note that if a Build is referenced in the `build` field, the command will be run from the build directory for that Build action. If that Build has `buildAtSource: true` set, the command will be run from the source directory of the Build action. If no `build` reference is set, the command is run from the source directory of this action.

| Type            | Required |
| --------------- | -------- |
| `array[string]` | No       |

### `spec.syncMode.timeout`

[spec](#spec) > [syncMode](#specsyncmode) > timeout

The maximum duration (in seconds) to wait for a for the `statusCommand` to return a zero exit code. Ignored if no `statusCommand` is set.

| Type     | Default | Required |
| -------- | ------- | -------- |
| `number` | `10`    | No       |


## Outputs

The following keys are available via the `${actions.deploy.<name>}` template string key for `exec`
modules.

### `${actions.deploy.<name>.buildPath}`

The build path of the action/module.

| Type     |
| -------- |
| `string` |

Example:

```yaml
my-variable: ${actions.deploy.my-deploy.buildPath}
```

### `${actions.deploy.<name>.name}`

The name of the action/module.

| Type     |
| -------- |
| `string` |

### `${actions.deploy.<name>.path}`

The source path of the action/module.

| Type     |
| -------- |
| `string` |

Example:

```yaml
my-variable: ${actions.deploy.my-deploy.path}
```

### `${actions.deploy.<name>.var.*}`

A map of all variables defined in the module.

| Type     | Default |
| -------- | ------- |
| `object` | `{}`    |

### `${actions.deploy.<name>.var.<variable-name>}`

| Type                                                 |
| ---------------------------------------------------- |
| `string \| number \| boolean \| link \| array[link]` |

### `${actions.deploy.<name>.version}`

The current version of the module.

| Type     |
| -------- |
| `string` |

Example:

```yaml
my-variable: ${actions.deploy.my-deploy.version}
```
