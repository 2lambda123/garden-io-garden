/*
 * Copyright (C) 2018-2022 Garden Technologies, Inc. <info@garden.io>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import { expect } from "chai"
import { describe } from "mocha"
import { includes } from "lodash"
import {
  pickKeys,
  getEnvVarName,
  exec,
  createOutputStream,
  makeErrorMsg,
  renderOutputStream,
  spawn,
  relationshipClasses,
  isValidDateInstance,
} from "../../../../src/util/util"
import { expectError } from "../../../helpers"
import { splitLast, splitFirst } from "../../../../src/util/string"
import { getLogger } from "../../../../src/logger/logger"
import { dedent } from "../../../../src/util/string"
import { safeDumpYaml } from "../../../../src/util/serialization"

function isLinuxOrDarwin() {
  return process.platform === "darwin" || process.platform === "linux"
}

describe("util", () => {
  describe("makeErrorMsg", () => {
    it("should return an error message", () => {
      const msg = makeErrorMsg({
        code: 1,
        cmd: "ls",
        args: ["some-dir"],
        error: "dir not found",
        output: "dir not found",
      })
      expect(msg).to.equal(dedent`
        Command "ls some-dir" failed with code 1:

        dir not found
      `)
    })
    it("should ignore emtpy args", () => {
      const msg = makeErrorMsg({
        code: 1,
        cmd: "ls",
        args: [],
        error: "dir not found",
        output: "dir not found",
      })
      expect(msg).to.equal(dedent`
        Command "ls" failed with code 1:

        dir not found
      `)
    })
    it("should include output if it's not the same as the error", () => {
      const msg = makeErrorMsg({
        code: 1,
        cmd: "ls some-dir",
        args: [],
        error: "dir not found",
        output: "dir not found and some more output",
      })
      expect(msg).to.equal(dedent`
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

      const msg = makeErrorMsg({
        code: 1,
        cmd: "ls some-dir",
        args: [],
        error: "dir not found",
        output: outputFull,
      })
      expect(msg).to.equal(dedent`
        Command "ls some-dir" failed with code 1:

        dir not found

        Here are the last 100 lines of the output:

        ${outputPartial}
      `)
    })
  })
  describe("exec", () => {
    before(function () {
      // These tests depend the underlying OS and are only executed on macOS and linux
      if (!isLinuxOrDarwin()) {
        // eslint-disable-next-line no-invalid-this
        this.skip()
      }
    })

    it("should successfully execute a command", async () => {
      const res = await exec("echo", ["hello"])
      expect(res.stdout).to.equal("hello")
    })

    it("should handle command and args in a single string", async () => {
      const res = await exec("echo hello && echo world", [], { shell: true })
      expect(res.stdout).to.equal("hello\nworld")
    })

    it("should optionally pipe stdout to an output stream", async () => {
      const logger = getLogger()
      const log = logger.createLog()

      await exec("echo", ["hello"], { stdout: createOutputStream(log) })

      expect(log.getLatestEntry().msg).to.equal(renderOutputStream("hello"))
    })

    it("should optionally pipe stderr to an output stream", async () => {
      const logger = getLogger()
      const log = logger.createLog()

      await exec("sh", ["-c", "echo hello 1>&2"], { stderr: createOutputStream(log) })

      expect(log.getLatestEntry().msg).to.equal(renderOutputStream("hello"))
    })

    it("should buffer outputs when piping to stream", async () => {
      const logger = getLogger()
      const log = logger.createLog()

      const res = await exec("echo", ["hello"], { stdout: createOutputStream(log) })

      expect(res.stdout).to.equal("hello")
    })

    it("should throw a standardised error message on error", async () => {
      try {
        // Using "sh -c" to get consistent output between operating systems
        await exec(`sh -c "echo hello error; exit 1"`, [], { shell: true })
      } catch (err) {
        expect(err.message).to.equal(
          makeErrorMsg({
            code: 1,
            cmd: `sh -c "echo hello error; exit 1"`,
            args: [],
            output: "hello error",
            error: "",
          })
        )
      }
    })
  })

  describe("spawn", () => {
    before(function () {
      // These tests depend on the underlying OS and are only executed on macOS and linux
      if (!isLinuxOrDarwin()) {
        // eslint-disable-next-line no-invalid-this
        this.skip()
      }
    })
    it("should throw a standardised error message on error", async () => {
      try {
        await spawn("ls", ["scottiepippen"])
      } catch (err) {
        // We're not using "sh -c" here since the output is not added to stdout|stderr if `tty: true` and
        // we therefore can't test the entire error message.
        if (process.platform === "darwin") {
          expect(err.message).to.equal(
            makeErrorMsg({
              code: 1,
              cmd: "ls scottiepippen",
              args: [],
              output: "ls: scottiepippen: No such file or directory",
              error: "ls: scottiepippen: No such file or directory",
            })
          )
        } else {
          expect(err.message).to.equal(
            makeErrorMsg({
              code: 2,
              cmd: "ls scottiepippen",
              args: [],
              output: "ls: cannot access 'scottiepippen': No such file or directory",
              error: "ls: cannot access 'scottiepippen': No such file or directory",
            })
          )
        }
      }
    })
  })

  describe("getEnvVarName", () => {
    it("should translate the service name to a name appropriate for env variables", async () => {
      expect(getEnvVarName("service-b")).to.equal("SERVICE_B")
    })
  })

  describe("pickKeys", () => {
    it("should pick keys from an object", () => {
      const obj = { a: 1, b: 2, c: 3 }
      expect(pickKeys(obj, ["a", "b"])).to.eql({ a: 1, b: 2 })
    })

    it("should throw if one or more keys are missing", async () => {
      const obj = { a: 1, b: 2, c: 3 }
      await expectError(
        () => pickKeys(obj, <any>["a", "foo", "bar"]),
        (err) => {
          expect(err.message).to.equal("Could not find key(s): foo, bar")
          expect(err.detail.missing).to.eql(["foo", "bar"])
          expect(err.detail.available).to.eql(["a", "b", "c"])
        }
      )
    })

    it("should use given description in error message", async () => {
      const obj = { a: 1, b: 2, c: 3 }
      await expectError(() => pickKeys(obj, <any>["a", "foo", "bar"], "banana"), {
        contains: "Could not find banana(s): foo, bar",
      })
    })
  })

  describe("splitFirst", () => {
    it("should split string on first occurrence of given delimiter", () => {
      expect(splitFirst("foo:bar:boo", ":")).to.eql(["foo", "bar:boo"])
    })

    it("should return the whole string as first element when no delimiter is found in string", () => {
      expect(splitFirst("foo", ":")).to.eql(["foo", ""])
    })
  })

  describe("splitLast", () => {
    it("should split string on last occurrence of given delimiter", () => {
      expect(splitLast("foo:bar:boo", ":")).to.eql(["foo:bar", "boo"])
    })

    it("should return the whole string as last element when no delimiter is found in string", () => {
      expect(splitLast("foo", ":")).to.eql(["", "foo"])
    })
  })

  describe("relationshipClasses", () => {
    it("should correctly partition related items", () => {
      const items = ["a", "b", "c", "d", "e", "f", "g", "ab", "bc", "cd", "de", "fg"]
      const isRelated = (s1: string, s2: string) => includes(s1, s2) || includes(s2, s1)
      // There's no "ef" element, so ["f", "fg", "g"] should be disjoint from the rest.
      expect(relationshipClasses(items, isRelated)).to.eql([
        ["a", "ab", "b", "bc", "c", "cd", "d", "de", "e"],
        ["f", "fg", "g"],
      ])
    })

    it("should return a single partition when only one item is passed", () => {
      const isRelated = (s1: string, s2: string) => s1[0] === s2[0]
      expect(relationshipClasses(["a"], isRelated)).to.eql([["a"]])
    })
  })

  describe("safeDumpYaml", () => {
    it("should exclude invalid values from resulting YAML", () => {
      const json = {
        foo: {
          a: "a",
          fn: () => {},
          deep: {
            undf: undefined,
            b: "b",
            deeper: {
              date: new Date("2020-01-01"),
              fn: () => {},
              c: "c",
            },
          },
          undf: undefined,
          d: "d",
        },
      }
      expect(safeDumpYaml(json)).to.eql(dedent`
      foo:
        a: a
        deep:
          b: b
          deeper:
            date: 2020-01-01T00:00:00.000Z
            c: c
        d: d\n
      `)
    })
  })
  describe("isValidDateInstance", () => {
    it("should validate a date instance and return the instance or undefined", () => {
      const validA = new Date()
      const validB = new Date("2023-02-01T19:46:42.266Z")
      const validC = new Date(1675280826163)

      // Tricking the compiler. We need to test for this because
      // date strings can be created from runtime values that we don't validate.
      const undef = undefined as any
      const invalidA = new Date(undef)
      const invalidB = new Date("foo")
      const invalidC = new Date("")

      expect(isValidDateInstance(validA)).to.be.true
      expect(isValidDateInstance(validB)).to.be.true
      expect(isValidDateInstance(validC)).to.be.true

      expect(isValidDateInstance(invalidA)).to.be.false
      expect(isValidDateInstance(invalidB)).to.be.false
      expect(isValidDateInstance(invalidC)).to.be.false
    })
  })
})
