# Variables and templating

This guide introduces the templating capabilities available in Garden configuration files, the available ways to provide variable values, and how to reference outputs across modules and providers.

## Template string basics

String configuration values in `garden.yml` can be templated to inject variables, information about the user's environment, references to other modules/services and more.

The syntax for templated strings is `${some.key}`. The key is looked up from the context available when resolving the string. The context depends on which top-level key the configuration value belongs to (`project` or `module`).

For example, for one service you might want to reference something from another module and expose it as an environment variable:

```yaml
kind: Module
name: some-module
services:
  - name: some-service
    ...
    env:
      OTHER_MODULE_VERSION: ${modules.other-module.version}
```

You can also inject a template variable into a string. For instance, you might need to include a module's
version as part of a URI:

```yaml
    ...
    env:
      OTHER_MODULE_ENDPOINT: http://other-module/api/${modules.other-module.version}
```

Note that while this syntax looks similar to template strings in Javascript, we don't allow arbitrary JS expressions. See the next section for the available expression syntax.

### Operators

You can use a variety of operators in template string expressions:

* Arithmetic: `*`, `/`, `%`, `+`, `-`
* Numeric comparison: `>=`, `<=`, `>`, `<`
* Equality: `==`, `!=`
* Logical: `&&`, `||`, ternary (`<test> ? <value if true> : <value if false>`)
* Unary: `!` (negation), `typeof` (returns the type of the following value as a string, e.g. `"boolean"` or `"number"`)

The arithmetic and numeric comparison operators can only be used for numeric literals and keys that resolve to numbers. The equality and logical operators work with any term.

Clauses are evaluated in standard precedence order, but you can also use parentheses to control evaluation order (e.g. `${(1 + 2) * (3 + 4)}` evaluates to 21).

These operators can be very handy, and allow you to tailor your configuration depending on different environments and other contextual variables.

Below are some examples of usage:

The `||` operator allows you to set default values:

```yaml
  # ...
  variables:
    log-level: ${local.env.LOG_LEVEL || "info"}
    namespace: ${local.env.CI_BRANCH || local.username || "default"}
```

The `==` and `!=` operators allow you to set boolean flags based on other variables:

```yaml
kind: Module
...
skipDeploy: ${environment.name == 'prod'}
...
```

```yaml
kind: Module
...
allowPublish: ${environment.name != 'prod'}
...
```

Ternary expressions, combined with comparison operators, can be useful when provisioning resources:

```yaml
kind: Module
type: container
...
services:
  replicas: "${environment.name == 'prod' ? 3 : 1}"
  ...
```

And the arithmetic operators can be handy when provisioning resources:

```yaml
kind: Module
type: container
...
services:
  replicas: ${var.default-replicas * 2}
  ...
```

## Project variables

A common use case for templating is to define variables in the project/environment configuration, and to use template strings to propagate values to modules in the project.

You can define them in your project configuration using the [`variables` key](../reference/config.md#variables), as well as the [`environment[].variables` key](../reference/config.md#environment-variables) for environment-specific values. You might, for example, define project defaults using the `variables` key, and then provide environment-specific overrides in the `environment[].variables` key for each environment.

The variables can then be configured via `${var.<key>}` template string keys. For example:

```yaml
kind: Project
...
variables:
  log-level: info
environments:
  - name: local
    ...
    variables:
      log-level: debug
  - name: remote
    ...
---
kind: Module
...
services:
  - name: my-service
    ...
    env:
      LOG_LEVEL: ${var.log-level}   # <- resolves to "debug" for the "local" environment, "info" for the "remote" env
```

### Variable files (varfiles)

You can also provide variables using "variable files" or _varfiles_. These work mostly like "dotenv" files or envfiles. However, they don't implicitly affect the environment of the Garden process and the configured services, but rather are added on top of the `variables` you define in your project `garden.yml`.

This can be very useful when you need to provide secrets and other contextual values to your stack. You could add your varfiles to your `.gitignore` file to keep them out of your repository, or use e.g. [git-crypt](https://github.com/AGWA/git-crypt), [BlackBox](https://github.com/StackExchange/blackbox) or [git-secret](https://git-secret.io/) to securely store the files in your Git repo.

By default, Garden will look for a `garden.env` file in your project root for project-wide variables, and a `garden.<env-name>.env` file for environment-specific variables. You can override the filename for each as well. The format of the files is the one supported by [dotenv](https://github.com/motdotla/dotenv#rules).

The order of precedence across the varfiles and project config fields is as follows (from highest to lowest):
_`garden.<env-name>.env` file_ > _`environment[].variables` field_ > _`garden.env` file_ > _`variables` field

Here's an example, where we have some project variables defined in our project config, and environment-specific values—including secret data—in varfiles:

```yaml
# garden.yml
kind: Project
...
variables:
  LOG_LEVEL: debug
environments:
  - name: local
    ...
  - name: remote
    ...
```

```plain
# garden.remote.env
log-level=info
database-password=fuin23liu54at90hiongl3g
```

```yaml
# my-service/garden.yml
kind: Module
...
services:
  - name: my-service
    ...
    env:
      LOG_LEVEL: ${var.log-level}
      DATABASE_PASSWORD: ${var.database-password}
```

## Provider outputs

Providers often expose useful variables that other provider configs and modules can reference, under `${providers.<name>.outputs.<key>}`. Each provider exposes different outputs, and some providers have dynamic output keys depending on their configuration.

For example, you may want to reference the app namespace from the [Kubernetes provider](../reference/providers/kubernetes.md) in module configs:

```yaml
kind: Module
type: helm
...
values:
  namespace: `${providers.kubernetes.outputs.app-namespace}`
```

Another good example is referencing outputs from Terraform stacks, via the [Terraform provider](./terraform.md):

```yaml
kind: Module
type: container
services:
  ...
  env:
    DATABASE_URL: `${providers.terraform.outputs.database_url}` # <- resolves the "database_url" stack output
```

Check out the individual [provider reference](../reference/providers/README.md) guides for details on what outputs each provider exposes.

## Module outputs

Modules often output useful information, that other modules can reference (provider configs cannot reference module outputs). Every module also exposes certain keys, like the module version.

For example, you may want to reference the image name and version of a [container module](../reference/module-types/container.md):

```yaml
kind: Module
type: helm
...
values:
  # Resolves to the image name of the module, with the module version as the tag (e.g. "my-image:abcdef12345")
  image: `${modules.my-image.outputs.deployment-image-name}:${modules.my-image.version}`
```

Check out the individual [module type reference](../reference/module-types/README.md) guides for details on what outputs each module type exposes.

## Runtime outputs

Template keys prefixed with `runtime.` have some special semantics. They are used to expose _runtime outputs_ from services and tasks, and therefore are resolved later than other template strings. _This means that you cannot use them for some fields, such as most identifiers, because those need to be resolved before validating the configuration._

That caveat aside, they can be very handy for passing information between services and tasks. For example, you can pass log outputs from one task to another:

```yaml
kind: Module
type: exec
name: module-a
tasks:
  - name: prep-task
    command: [echo, "my task output"]
---
kind: Module
type: container
name: my-container
services:
  - name: my-service
    dependencies: [task-a]
    env:
      PREP_TASK_OUTPUT: ${runtime.tasks.prep-task.outputs.log}  # <- resolves to "my task output"
```

Here the output from `prep-task` is copied to an environment variable for `my-service`. _Note that you currently need to explicitly declare `task-a` as a dependency for this to work._

For a practical use case, you might for example make a task that provisions some infrastructure or prepares some data, and then passes information about it to services.

Different module types expose different output keys for their services and tasks. Please refer to the [module type reference docs](https://docs.garden.io/reference/module-types) for details.

## Next steps

For a full reference of the keys available in template strings, please look at the [Template Strings Reference](../reference/template-strings.md), as well as individual [providers](../refrence/providers/README.md) for provider outputs, and [module types](../reference/module-types/README.md) for module and runtime output keys.
