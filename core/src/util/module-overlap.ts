/*
 * Copyright (C) 2018-2023 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
import { posix, resolve } from "path"
import { ModuleConfig, ModuleFileSpec } from "../config/module"
import pathIsInside from "path-is-inside"
import { intersection, sortBy } from "lodash"
import chalk from "chalk"
import { naturalList } from "./string"
import dedent from "dedent"
import { isTruthy } from "./util"
import { InternalError } from "../exceptions"

export const moduleOverlapTypes = ["path", "generateFiles"] as const
export type ModuleOverlapType = typeof moduleOverlapTypes[number]

/**
 * Data structure to describe overlapping modules.
 */
export interface ModuleOverlap {
  config: ModuleConfig
  overlaps: ModuleConfig[]
  type: ModuleOverlapType
  generateFilesOverlaps?: string[]
}

type ModuleOverlapFinder = (
  c: ModuleConfig
) => {
  matches: ModuleConfig[]
  type?: ModuleOverlapType
  generateFilesOverlaps?: string[]
}

const moduleNameComparator = (a, b) => (a.name > b.name ? 1 : -1)

function resolveGenerateFilesTargetPaths(modulePath: string, generateFiles: ModuleFileSpec[]): string[] {
  return generateFiles.map((f) => f.targetPath).map((p) => resolve(modulePath, ...p.split(posix.sep)))
}

/**
 * Returns a list of overlapping modules.
 *
 * If a module does not set `include` or `exclude`, and another module is in its path (including
 * when the other module has the same path), the module overlaps with the other module.
 *
 * If two modules have `generateFiles`, and at least one `generateFiles.targetPath` is the same in both modules,
 * then the modules overlap.
 */
export function detectModuleOverlap({
  projectRoot,
  gardenDirPath,
  moduleConfigs,
}: {
  projectRoot: string
  gardenDirPath: string
  moduleConfigs: ModuleConfig[]
}): ModuleOverlap[] {
  // Don't consider overlap between disabled modules, or where one of the modules is disabled
  const enabledModules = moduleConfigs.filter((m) => !m.disabled)

  const findModulePathOverlaps: ModuleOverlapFinder = (config: ModuleConfig) => {
    if (!!config.include || !!config.exclude) {
      return { matches: [] }
    }
    const matches = enabledModules
      .filter(
        (compare) =>
          config.name !== compare.name &&
          // Don't consider overlap between modules in root and those in the .garden directory
          pathIsInside(compare.path, config.path) &&
          !(config.path === projectRoot && pathIsInside(compare.path, gardenDirPath))
      )
      .sort(moduleNameComparator)
    return { matches, type: "path" }
  }

  const findGenerateFilesOverlaps: ModuleOverlapFinder = (config: ModuleConfig) => {
    // Nothing to return if the current module has no `generateFiles` defined
    if (!config.generateFiles) {
      return { matches: [] }
    }

    const targetPaths = resolveGenerateFilesTargetPaths(config.path, config.generateFiles)
    const findTargetPathOverlaps = (compare: ModuleConfig): string[] => {
      // Do not compare module against itself
      if (config.name === compare.name) {
        return []
      }
      // Skip the modules without `generateFiles`
      if (!compare.generateFiles) {
        return []
      }
      const compareTargetPaths = resolveGenerateFilesTargetPaths(compare.path, compare.generateFiles)
      return intersection(targetPaths, compareTargetPaths)
    }

    const matches: ModuleConfig[] = []
    const generateFilesOverlaps: string[] = []
    for (const enabledModule of enabledModules) {
      const targetPathOverlaps = findTargetPathOverlaps(enabledModule)
      if (targetPathOverlaps.length > 0) {
        matches.push(enabledModule)
      }
      generateFilesOverlaps.push(...targetPathOverlaps)
    }

    return { matches: matches.sort(moduleNameComparator), type: "generateFiles", generateFilesOverlaps }
  }

  const moduleOverlapFinders: ModuleOverlapFinder[] = [findModulePathOverlaps, findGenerateFilesOverlaps]
  let overlaps: ModuleOverlap[] = []
  for (const config of enabledModules) {
    for (const moduleOverlapFinder of moduleOverlapFinders) {
      const { matches, type, generateFilesOverlaps } = moduleOverlapFinder(config)
      if (matches.length > 0) {
        if (!type) {
          throw new InternalError(
            "Got some module overlap errors with undefined type. This is a bug, please report it.",
            { config, overlaps: matches }
          )
        }
        overlaps.push({ config, overlaps: matches, type, generateFilesOverlaps })
      }
    }
  }
  return overlaps
}

export interface OverlapErrorDescription {
  detail: {
    overlappingModules: { module: { path: string; name: string }; overlaps: { path: string; name: string }[] }[]
  }
  message: string
}

type ModuleOverlapRenderer = (projectRoot: string, moduleOverlaps: ModuleOverlap[]) => OverlapErrorDescription

const makeGenerateFilesOverlapError: ModuleOverlapRenderer = (
  projectRoot: string,
  moduleOverlaps: ModuleOverlap[]
): OverlapErrorDescription => {
  const moduleOverlapList = sortBy(moduleOverlaps, (o) => o.config.name).map(
    ({ config, overlaps, generateFilesOverlaps }) => {
      const formatted = overlaps.map((o) => {
        return `${chalk.bold(o.name)}`
      })
      // const generateFilesOverlapList =
      return `Module ${chalk.bold(config.name)} overlaps with module(s) ${naturalList(formatted)} in ${naturalList(
        generateFilesOverlaps || []
      )}.`
    }
  )

  const message = chalk.red(dedent`
      Found multiple enabled modules that share the same value(s) in ${chalk.bold("generateFiles[].targetPath")}:

      ${moduleOverlapList.join("\n\n")}
    `)
  // Sanitize error details
  const overlappingModules = moduleOverlaps.map(({ config, overlaps }) => {
    return {
      module: { name: config.name, path: resolve(projectRoot, config.path) },
      overlaps: overlaps.map(({ name, path }) => ({ name, path: resolve(projectRoot, path) })),
    }
  })
  // TODO: more details
  return {
    message,
    detail: { overlappingModules },
  }
}

const makePathOverlapError: ModuleOverlapRenderer = (
  projectRoot: string,
  moduleOverlaps: ModuleOverlap[]
): OverlapErrorDescription => {
  const overlapList = sortBy(moduleOverlaps, (o) => o.config.name).map(({ config, overlaps }) => {
    const formatted = overlaps.map((o) => {
      const detail = o.path === config.path ? "same path" : "nested"
      return `${chalk.bold(o.name)} (${detail})`
    })
    return `Module ${chalk.bold(config.name)} overlaps with module(s) ${naturalList(formatted)}.`
  })
  const message = chalk.red(dedent`
      Found multiple enabled modules that share the same garden.yml file or are nested within another:

      ${overlapList.join("\n\n")}

      If this was intentional, there are two options to resolve this error:

      - You can add ${chalk.bold("include")} and/or ${chalk.bold("exclude")} directives on the affected modules.
        With explicitly including / excluding files, the modules are actually allowed to overlap in case that is
        what you want.
      - You can use the ${chalk.bold("disabled")} directive to make sure that only one of the modules is enabled
        in any given moment. For example, you can make sure that the modules are enabled only in their exclusive
        environment.
    `)
  // Sanitize error details
  const overlappingModules = moduleOverlaps.map(({ config, overlaps }) => {
    return {
      module: { name: config.name, path: resolve(projectRoot, config.path) },
      overlaps: overlaps.map(({ name, path }) => ({ name, path: resolve(projectRoot, path) })),
    }
  })
  return { message, detail: { overlappingModules } }
}

// This explicit type ensures that every `ModuleOverlapType` has a defined renderer
const moduleOverlapRenderers: { [k in ModuleOverlapType]: ModuleOverlapRenderer } = {
  path: makePathOverlapError,
  generateFiles: makeGenerateFilesOverlapError,
}

function renderOverlapForType({
  projectRoot,
  moduleOverlaps,
  moduleOverlapType,
}: {
  moduleOverlapType: ModuleOverlapType
  moduleOverlaps: ModuleOverlap[]
  projectRoot: string
}): OverlapErrorDescription | undefined {
  const filteredOverlaps = moduleOverlaps.filter((m) => m.type === moduleOverlapType)
  if (filteredOverlaps.length === 0) {
    return undefined
  }
  const renderer = moduleOverlapRenderers[moduleOverlapType]
  return renderer(projectRoot, filteredOverlaps)
}

export function makeOverlapErrors(projectRoot: string, moduleOverlaps: ModuleOverlap[]): OverlapErrorDescription[] {
  return moduleOverlapTypes
    .map((moduleOverlapType) =>
      renderOverlapForType({
        moduleOverlapType,
        moduleOverlaps,
        projectRoot,
      })
    )
    .filter(isTruthy)
}