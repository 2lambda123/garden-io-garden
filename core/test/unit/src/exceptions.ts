/*
 * Copyright (C) 2018-2023 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { expect } from "chai"
import {
  ChildProcessError,
  ConfigurationError,
  GardenError,
  RuntimeError,
  StackTraceMetadata,
  getStackTraceMetadata,
} from "../../../src/exceptions"
import dedent from "dedent"

describe("GardenError", () => {
  // helper to avoid dealing with changing line numbers
  const filterTrace = (metadata) => {
    return metadata.map((m) => {
      return {
        functionName: m.functionName,
        lineNumber: undefined,
        relativeFileName: m.relativeFileName,
      }
    })
  }

  it("should return stack trace metadata", async () => {
    let error: GardenError

    try {
      throw new RuntimeError({ message: "test exception" })
    } catch (err) {
      error = err
    }

    const stackTrace = getStackTraceMetadata(error)

    const expectedSubset: StackTraceMetadata[] = [
      {
        relativeFileName: "exceptions.ts",
        lineNumber: undefined,
        functionName: "Context.<anonymous>",
      },
      {
        functionName: "Test.Runnable.run",
        lineNumber: undefined,
        relativeFileName: "mocha/lib/runnable.js",
      },
    ]

    expect(stackTrace).to.not.be.undefined

    // make sure we set line numbers
    // we avoid testing them in deep equals since they are not reliable for tests
    expect(stackTrace.metadata.at(0)).to.not.be.undefined
    expect(stackTrace.metadata.at(0)?.lineNumber).to.not.be.undefined

    expect(filterTrace(stackTrace.metadata)).to.deep.include.members(expectedSubset)
  })

  it("should handle empty stack trace", async () => {
    const error = new RuntimeError({ message: "test exception" })

    error.stack = ""
    const stackTrace = getStackTraceMetadata(error)
    expect(stackTrace).to.eql({ metadata: [], wrappedMetadata: undefined })
  })

  it("should return list of stack trace entries", async () => {
    const error = new RuntimeError({ message: "test exception" })

    error.stack = `Error: test exception
    at Context.<anonymous> (/path/to/src/utils/exceptions.ts:17:13)
    at Test.Runnable.run (/path/to/node_modules/mocha/lib/runnable.js:354:5)
    at processImmediate (node:internal/timers:471:21)`

    const stackTrace = getStackTraceMetadata(error)
    expect(filterTrace(stackTrace.metadata)).to.eql([
      { relativeFileName: "utils/exceptions.ts", lineNumber: undefined, functionName: "Context.<anonymous>" },
      { relativeFileName: "mocha/lib/runnable.js", lineNumber: undefined, functionName: "Test.Runnable.run" },
      { relativeFileName: "timers", lineNumber: undefined, functionName: "processImmediate" },
    ])
  })

  it("should return wrapped stack trace metadata", async () => {
    const wrappedError = new ConfigurationError({ message: "test exception" })
    wrappedError.stack = `Error: config exception
    at Context.<anonymous> (/path/to/src/utils/exceptions.ts:17:13)
    at Test.Runnable.run (/path/to/node_modules/mocha/lib/runnable.js:354:5)
    at processImmediate (node:internal/timers:471:21)`

    const error = new RuntimeError({ message: "test exception", wrappedErrors: [wrappedError] })

    const stackTrace = getStackTraceMetadata(error)

    expect(stackTrace.wrappedMetadata).to.have.length(1)
    expect(filterTrace(stackTrace.wrappedMetadata?.at(0))).to.eql([
      { relativeFileName: "utils/exceptions.ts", lineNumber: undefined, functionName: "Context.<anonymous>" },
      { relativeFileName: "mocha/lib/runnable.js", lineNumber: undefined, functionName: "Test.Runnable.run" },
      { relativeFileName: "timers", lineNumber: undefined, functionName: "processImmediate" },
    ])
  })
})

describe("ChildProcessError", () => {
  it("formats an appropriate error message", () => {
    const err = new ChildProcessError({
      code: 1,
      cmd: "ls",
      args: ["some-dir"],
      stderr: "dir not found",
      stdout: "",
      output: "dir not found",
    })
    expect(err.message).to.equal(dedent`
      Command "ls some-dir" failed with code 1:

      dir not found
    `)
  })
  it("should ignore emtpy args", () => {
    const err = new ChildProcessError({
      code: 1,
      cmd: "ls",
      args: [],
      stderr: "dir not found",
      stdout: "",
      output: "dir not found",
    })
    expect(err.message).to.equal(dedent`
      Command "ls" failed with code 1:

      dir not found
    `)
  })
  it("should include output if it's not the same as the error", () => {
    const err = new ChildProcessError({
      code: 1,
      cmd: "ls some-dir",
      args: [],
      stderr: "dir not found",
      stdout: " and some more output",
      output: "dir not found and some more output",
    })
    expect(err.message).to.equal(dedent`
      Command "ls some-dir" failed with code 1:

      dir not found

      Here's the full output:

      dir not found and some more output
    `)
  })
  it("should include the last 100 lines of output if output is very long", () => {
    const output = "All work and no play\n"
    const outputFull = output.repeat(102)
    const outputPartial = output.repeat(99) // This makes 100 lines in total

    const err = new ChildProcessError({
      code: 1,
      cmd: "ls some-dir",
      args: [],
      stderr: "dir not found",
      stdout: outputFull,
      output: outputFull,
    })
    expect(err.message).to.equal(dedent`
      Command "ls some-dir" failed with code 1:

      dir not found

      Here are the last 100 lines of the output:

      ${outputPartial}
    `)
  })
})
