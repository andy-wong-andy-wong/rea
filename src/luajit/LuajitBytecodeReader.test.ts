import { describe, expect, it } from "vitest";
import { luajitGolden } from "../../tests/fixtures/luajit/bytecode.js";
import {
  LuajitFormatFailure,
  LuajitResourceFailure,
  readLuajitBytecode,
} from "./LuajitBytecodeReader.js";

const read = (bytes: Buffer, budget = 8 * 1024 * 1024) =>
  readLuajitBytecode(bytes, budget);
const failure = (bytes: Buffer) => {
  try {
    read(bytes);
  } catch (cause) {
    return cause;
  }
  throw new Error("expected a failure");
};

describe("real luajit -b dumps", () => {
  it("reads a stripped dump, indexing constants by bytecode operand", () => {
    const dump = read(luajitGolden("stripped"));
    expect(dump.header).toMatchObject({
      version: 2,
      flags: { stripped: true, ffi: true, fr2: true, big_endian: false },
      chunk_name: null,
    });
    expect(dump.main_prototype).toBe(1);
    expect(dump.trailing_bytes).toBe(0);
    const [inner, main] = dump.prototypes;
    // FNEW 1 0 / KSTR 2 / TDUP 2 1 / KCDATA 3 / KNUM 6 0 in `luajit -bl`.
    expect(inner).toMatchObject({
      parameter_count: 2,
      upvalue_refs: [0xc000],
      instruction_count: 5,
      constants: { numbers: [{ index: 0, value: 1.5 }] },
      debug: null,
    });
    expect(main?.constants.gc.map(({ index, kind }) => [index, kind])).toEqual([
      [3, "uint64"],
      [2, "string"],
      [1, "table"],
      [0, "child"],
    ]);
    expect(main?.constants.gc[0]).toMatchObject({ value: "12345678901" });
    expect(main?.constants.gc[3]).toMatchObject({ prototype: 0 });
    expect(main?.constants.gc[2]).toMatchObject({
      array: [{ kind: "nil" }, { value: 1 }, { value: 2 }],
      hash: [
        { key: { value: 3.5 }, value: { value: true } },
        { key: { text: "x" }, value: { text: "hi" } },
      ],
    });
    expect(main?.constants.numbers[0]).toMatchObject({
      bits: "0x42dfffffffffffc0",
      value: 140737488355327,
    });
  });

  it("reads debug names, loop variables and exact ranges", () => {
    const dump = read(luajitGolden("debug"));
    expect(dump.header.chunk_name).toEqual({ text: "@a.lua" });
    expect(dump.prototypes[0]?.debug).toMatchObject({
      first_line: 2,
      upvalue_names: [{ text: "up" }],
      variables: [
        { name: { text: "a" }, start_pc: 0, end_pc: 6 },
        { name: { text: "b" }, start_pc: 0, end_pc: 6 },
      ],
    });
    const loops = read(luajitGolden("loops"));
    expect(loops.main_prototype).toBe(2);
    const names = loops.prototypes[1]?.debug?.variables?.map(
      ({ name, builtin }) => [name, builtin],
    );
    expect(names?.slice(0, 3)).toEqual([
      [{ text: "(for index)" }, true],
      [{ text: "(for limit)" }, true],
      [{ text: "(for step)" }, true],
    ]);
    const gc = loops.prototypes[2]?.constants.gc;
    expect(gc?.find((c) => c.kind === "int64")).toMatchObject({ value: "-1" });
    expect(gc?.find((c) => c.kind === "complex")).toMatchObject({
      real: { value: 0 },
      imaginary: { value: 1 },
    });
    expect(loops.prototypes[2]?.constants.numbers).toMatchObject([
      { bits: "0x7e37e43c8800759c", value: 1e300 },
      { kind: "integer", value: 0 },
    ]);
  });

  it("keeps non-UTF-8 strings as bytes and decodes multi-byte tags and line info", () => {
    const main = read(luajitGolden("wide")).prototypes[1];
    expect(main?.constants.gc).toContainEqual({
      index: 2,
      kind: "string",
      text: null,
      bytes_base64: "/w==",
    });
    expect(main?.constants.gc).toContainEqual({
      index: 0,
      kind: "string",
      text: "x".repeat(130),
    });
    expect(read(luajitGolden("wide")).prototypes[0]?.debug).toMatchObject({
      line_info_entry_bytes: 2,
      line_count: 303,
    });
  });
});

describe("unsupported and malformed input", () => {
  it.each([
    ["PUC-Lua", Buffer.from("\x1bLuaQ\x00", "latin1"), /PUC-Lua/],
    ["not bytecode", Buffer.from("print(1)"), /signature/],
    ["empty", Buffer.alloc(0), /signature/],
  ])("rejects %s as unsupported", (_name, bytes, message) => {
    expect(failure(bytes)).toMatchObject({
      kind: "unsupported",
      message: expect.stringMatching(message),
    });
  });

  it("rejects unknown versions and flag bits as unsupported", () => {
    const version = luajitGolden("stripped");
    version[3] = 9;
    expect(failure(version)).toMatchObject({ kind: "unsupported" });
    const flags = luajitGolden("stripped");
    flags[4] = 0x1e;
    expect(failure(flags)).toMatchObject({ kind: "unsupported" });
  });

  it("rejects every truncation of a valid dump as malformed", () => {
    const bytes = luajitGolden("debug");
    for (let size = 3; size < bytes.length; size++) {
      const cause = failure(bytes.subarray(0, size));
      expect(cause).toBeInstanceOf(LuajitFormatFailure);
      expect(cause).toMatchObject({ kind: "malformed" });
    }
  });

  it("rejects prototype lengths and counts that disagree with their contents", () => {
    const longer = luajitGolden("stripped");
    longer[5]! += 1;
    expect(failure(longer)).toBeInstanceOf(LuajitFormatFailure);
    const huge = luajitGolden("stripped");
    huge.set([0xff, 0xff, 0xff, 0xff, 0x0f], 11);
    expect(failure(huge)).toMatchObject({ kind: "malformed" });
  });

  it("rejects unreferenced prototypes and missing prototypes", () => {
    const stripped = luajitGolden("stripped");
    const inner = stripped.subarray(5, 6 + stripped[5]!);
    const twice = Buffer.concat([stripped.subarray(0, 5), inner, inner, Buffer.alloc(1)]);
    expect(failure(twice)).toMatchObject({
      kind: "malformed",
      message: expect.stringMatching(/no parent references/),
    });
    expect(failure(Buffer.from("1b4c4a020e00", "hex"))).toMatchObject({
      kind: "malformed",
      message: expect.stringMatching(/no prototype/),
    });
  });

  it("keeps decoded facts when the debug layout is unreadable", () => {
    const bytes = luajitGolden("debug");
    bytes[bytes.length - 2] = 0x05;
    const debug = read(bytes).prototypes[1]?.debug;
    expect(debug).toMatchObject({ upvalue_names: [], variables: null });
  });

  it("reports trailing bytes instead of ignoring them", () => {
    const bytes = Buffer.concat([luajitGolden("stripped"), Buffer.from("zz")]);
    expect(read(bytes).trailing_bytes).toBe(2);
  });

  it("fails closed when decoded structure exceeds the output budget", () => {
    expect(() => read(luajitGolden("loops"), 1024)).toThrow(
      LuajitResourceFailure,
    );
  });
});
