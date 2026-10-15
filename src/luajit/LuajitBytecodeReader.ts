import type { LuajitBytecode } from "../domain/luajit/luajitBytecode.js";

type Header = LuajitBytecode["header"];
type Prototype = LuajitBytecode["prototypes"][number];
type GcConstant = Prototype["constants"]["gc"][number];
type NumberConstant = Prototype["constants"]["numbers"][number];
type Debug = NonNullable<Prototype["debug"]>;
type Text = { text: string } | { text: null; bytes_base64: string };
type TableValue = Extract<GcConstant, { kind: "table" }>["array"][number];

/** Distinguish corrupt LuaJIT dumps from files outside the supported format. */
export class LuajitFormatFailure extends Error {
  constructor(
    readonly kind: "malformed" | "unsupported",
    message: string,
  ) {
    super(message);
    this.name = "LuajitFormatFailure";
  }
}

/** Decoded structure would exceed the inline output budget. */
export class LuajitResourceFailure extends Error {
  constructor(
    readonly maximum_bytes: number,
    message: string,
  ) {
    super(message);
    this.name = "LuajitResourceFailure";
  }
}

const malformed = (message: string) =>
  new LuajitFormatFailure("malformed", message);

const FLAG_BIG_ENDIAN = 0x01;
const FLAG_STRIPPED = 0x02;
const FLAG_FFI = 0x04;
const FLAG_FR2 = 0x08;
const KNOWN_FLAGS = FLAG_BIG_ENDIAN | FLAG_STRIPPED | FLAG_FFI | FLAG_FR2;
const GC_CHILD = 0;
const GC_TABLE = 1;
const GC_INT64 = 2;
const GC_UINT64 = 3;
const GC_COMPLEX = 4;
const GC_STRING = 5;
const TABLE_NIL = 0;
const TABLE_FALSE = 1;
const TABLE_TRUE = 2;
const TABLE_INTEGER = 3;
const TABLE_NUMBER = 4;
const TABLE_STRING = 5;
/** Debug variable codes 1..6 are LuaJIT's built-in loop names; 0 ends the list. */
const BUILTIN_VARIABLES = [
  "",
  "(for index)",
  "(for limit)",
  "(for step)",
  "(for generator)",
  "(for state)",
  "(for control)",
] as const;
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const textOf = (bytes: Buffer): Text => {
  try {
    return { text: UTF8.decode(bytes) };
  } catch {
    return { text: null, bytes_base64: Buffer.from(bytes).toString("base64") };
  }
};

const hex32 = (word: number) => word.toString(16).padStart(8, "0");

const doubleOf = (lo: number, hi: number) => {
  const view = new DataView(new ArrayBuffer(8));
  view.setUint32(0, hi);
  view.setUint32(4, lo);
  const value = view.getFloat64(0);
  return {
    bits: `0x${hex32(hi)}${hex32(lo)}`,
    value: Number.isFinite(value) ? value : null,
  };
};

/** Bounded cursor; every read is checked against its enclosing range. */
class Cursor {
  constructor(
    readonly bytes: Buffer,
    public pos: number,
    readonly end: number,
  ) {}

  get remaining(): number {
    return this.end - this.pos;
  }

  byte(label: string): number {
    if (this.pos >= this.end) throw malformed(`${label} is truncated`);
    return this.bytes[this.pos++]!;
  }

  take(size: number, label: string): Buffer {
    if (size > this.remaining) throw malformed(`${label} is truncated`);
    const value = this.bytes.subarray(this.pos, this.pos + size);
    this.pos += size;
    return value;
  }

  /** 32-bit ULEB128; LuaJIT's reader silently truncates longer values, this one rejects them. */
  uleb(label: string): number {
    let value = 0;
    for (let index = 0; index < 5; index++) {
      const byte = this.byte(label);
      value += (byte & 0x7f) * 2 ** (7 * index);
      if (byte < 0x80) {
        if (value > 0xffffffff) break;
        return value;
      }
    }
    throw malformed(`${label} is not a 32-bit ULEB128 value`);
  }

  /** Number-constant encoding: bit 0 selects a double, the rest is a ULEB128 shifted by one bit. */
  uleb33(label: string): { readonly is_double: boolean; readonly value: number } {
    const first = this.byte(label);
    let value = (first >> 1) & 0x3f;
    if (first >= 0x80)
      for (let index = 0; ; index++) {
        if (index === 4) throw malformed(`${label} is not a 32-bit value`);
        const byte = this.byte(label);
        value += (byte & 0x7f) * 2 ** (6 + 7 * index);
        if (byte < 0x80) break;
      }
    if (value > 0xffffffff) throw malformed(`${label} is not a 32-bit value`);
    return { is_double: (first & 1) === 1, value };
  }

  /** NUL-terminated string, or undefined when no terminator remains. */
  cstring(label: string): Buffer | undefined {
    const end = this.bytes.indexOf(0, this.pos);
    if (end < 0 || end >= this.end) return undefined;
    return this.take(end - this.pos + 1, label).subarray(0, -1);
  }
}

const readHeader = (bytes: Buffer): { header: Header; cursor: Cursor } => {
  if (bytes.subarray(0, 4).toString("latin1") === "\x1bLua")
    throw new LuajitFormatFailure(
      "unsupported",
      "PUC-Lua bytecode is not supported; only LuaJIT dumps are read",
    );
  if (bytes.subarray(0, 3).toString("latin1") !== "\x1bLJ")
    throw new LuajitFormatFailure(
      "unsupported",
      "Missing the ESC L J LuaJIT bytecode signature",
    );
  const cursor = new Cursor(bytes, 3, bytes.length);
  const version = cursor.byte("Version");
  if (version !== 1 && version !== 2)
    throw new LuajitFormatFailure(
      "unsupported",
      `LuaJIT bytecode dump version ${version} is not supported`,
    );
  const raw = cursor.uleb("Header flags");
  if ((raw & ~KNOWN_FLAGS) !== 0)
    throw new LuajitFormatFailure(
      "unsupported",
      `Header flags 0x${raw.toString(16)} contain unknown bits`,
    );
  const stripped = (raw & FLAG_STRIPPED) !== 0;
  const chunkName = stripped
    ? null
    : textOf(cursor.take(cursor.uleb("Chunk name length"), "Chunk name"));
  const header = {
    version,
    flags: {
      raw,
      big_endian: (raw & FLAG_BIG_ENDIAN) !== 0,
      stripped,
      ffi: (raw & FLAG_FFI) !== 0,
      fr2: (raw & FLAG_FR2) !== 0,
    },
    chunk_name: chunkName,
    bytes: cursor.pos,
  };
  return { header, cursor };
};

/** Debug blob: line info, then upvalue names, then variable ranges. */
const readDebugNames = (
  blob: Buffer,
  lineInfoBytes: number,
  upvalueCount: number,
  charge: (cost: number) => void,
): Pick<Debug, "upvalue_names" | "variables"> => {
  const unreadable = { upvalue_names: null, variables: null };
  if (lineInfoBytes > blob.length) return unreadable;
  const names = new Cursor(blob, lineInfoBytes, blob.length);
  const upvalueNames: Text[] = [];
  for (let index = 0; index < upvalueCount; index++) {
    const name = names.cstring("Upvalue name");
    if (name === undefined) return unreadable;
    charge(32 + name.length * 2);
    upvalueNames.push(textOf(name));
  }
  const variables: NonNullable<Debug["variables"]> = [];
  let start = 0;
  try {
    for (;;) {
      const code = names.byte("Variable name");
      if (code === 0) break;
      const builtin = code < BUILTIN_VARIABLES.length;
      if (!builtin) names.pos--;
      const name = builtin
        ? Buffer.from(BUILTIN_VARIABLES[code]!)
        : names.cstring("Variable name");
      if (name === undefined) throw malformed("Variable name is unterminated");
      start += names.uleb("Variable start");
      charge(96 + name.length * 2);
      variables.push({
        name: textOf(name),
        builtin,
        start_pc: start,
        end_pc: start + names.uleb("Variable length"),
      });
    }
  } catch (cause) {
    if (cause instanceof LuajitFormatFailure)
      return { upvalue_names: upvalueNames, variables: null };
    throw cause;
  }
  return {
    upvalue_names: upvalueNames,
    variables: names.remaining === 0 ? variables : null,
  };
};

/** Decodes prototypes in dump order; children precede their parents. */
class Decoder {
  readonly prototypes: Prototype[] = [];
  /** Prototypes not yet claimed by a parent constant. */
  readonly unclaimed: number[] = [];
  #spent = 0;

  constructor(
    readonly bytes: Buffer,
    readonly header: Header,
    readonly budget: number,
  ) {
    this.charge(256);
  }

  /** Approximate JSON size of decoded values, charged before they accumulate. */
  charge(cost: number): void {
    this.#spent += cost;
    if (this.#spent > this.budget)
      throw new LuajitResourceFailure(
        this.budget,
        "Decoded structure exceeds the inline output budget",
      );
  }

  text(bytes: Buffer): Text {
    this.charge(48 + bytes.length * 2);
    return textOf(bytes);
  }

  tableValue(body: Cursor): TableValue {
    const tag = body.uleb("Table constant tag");
    if (tag >= TABLE_STRING)
      return {
        kind: "string",
        ...this.text(body.take(tag - TABLE_STRING, "Table string")),
      };
    this.charge(48);
    switch (tag) {
      case TABLE_NIL:
        return { kind: "nil" };
      case TABLE_FALSE:
      case TABLE_TRUE:
        return { kind: "boolean", value: tag === TABLE_TRUE };
      case TABLE_INTEGER:
        return { kind: "integer", value: body.uleb("Table integer") | 0 };
      case TABLE_NUMBER: {
        const lo = body.uleb("Table number");
        return { kind: "number", ...doubleOf(lo, body.uleb("Table number")) };
      }
      default:
        throw malformed(`Unknown table constant tag ${tag}`);
    }
  }

  gcConstant(body: Cursor, index: number): GcConstant {
    const tag = body.uleb("GC constant tag");
    if (tag >= GC_STRING)
      return {
        index,
        kind: "string",
        ...this.text(body.take(tag - GC_STRING, "String constant")),
      };
    this.charge(64);
    switch (tag) {
      case GC_CHILD: {
        const prototype = this.unclaimed.pop();
        if (prototype === undefined)
          throw malformed("Child prototype constant has no prototype");
        return { index, kind: "child", prototype };
      }
      case GC_TABLE: {
        const arrayCount = body.uleb("Table array count");
        const hashCount = body.uleb("Table hash count");
        if (arrayCount + hashCount * 2 > body.remaining)
          throw malformed("Table counts exceed the prototype");
        const array = Array.from({ length: arrayCount }, () =>
          this.tableValue(body),
        );
        const hash = Array.from({ length: hashCount }, () => ({
          key: this.tableValue(body),
          value: this.tableValue(body),
        }));
        return { index, kind: "table", array, hash };
      }
      case GC_INT64:
      case GC_UINT64: {
        const lo = body.uleb("64-bit constant");
        const bits = (BigInt(body.uleb("64-bit constant")) << 32n) | BigInt(lo);
        const signed = tag === GC_INT64;
        return {
          index,
          kind: signed ? "int64" : "uint64",
          value: (signed ? BigInt.asIntN(64, bits) : bits).toString(),
        };
      }
      case GC_COMPLEX: {
        const [reLo, reHi, imLo, imHi] = [0, 0, 0, 0].map(() =>
          body.uleb("Complex constant"),
        ) as [number, number, number, number];
        return {
          index,
          kind: "complex",
          real: doubleOf(reLo, reHi),
          imaginary: doubleOf(imLo, imHi),
        };
      }
      default:
        throw malformed(`Unknown GC constant tag ${tag}`);
    }
  }

  numberConstant(body: Cursor, index: number): NumberConstant {
    const { is_double, value } = body.uleb33("Number constant");
    return is_double
      ? {
          index,
          kind: "number",
          ...doubleOf(value, body.uleb("Number constant")),
        }
      : { index, kind: "integer", value: value | 0 };
  }

  debug(
    body: Cursor,
    shape: {
      readonly bytes: number;
      readonly first_line: number;
      readonly line_count: number;
      readonly instructions: number;
      readonly upvalues: number;
    },
  ): Debug {
    const entry = shape.line_count < 256 ? 1 : shape.line_count < 65536 ? 2 : 4;
    const blob = body.take(shape.bytes, "Debug information");
    return {
      bytes: shape.bytes,
      first_line: shape.first_line,
      line_count: shape.line_count,
      line_info_entry_bytes: entry,
      ...readDebugNames(
        blob,
        shape.instructions * entry,
        shape.upvalues,
        (cost) => this.charge(cost),
      ),
    };
  }

  /** Decode the prototype whose length prefix ends at `start`. */
  prototype(start: number, length: number): Prototype {
    const body = new Cursor(this.bytes, start, start + length);
    const flags = body.byte("Prototype flags");
    const parameterCount = body.byte("Parameter count");
    const frameSize = body.byte("Frame size");
    const upvalueCount = body.byte("Upvalue count");
    const gcCount = body.uleb("GC constant count");
    const numberCount = body.uleb("Number constant count");
    const instructionCount = body.uleb("Instruction count");
    const shape = { bytes: 0, first_line: 0, line_count: 0 };
    if (!this.header.flags.stripped) {
      shape.bytes = body.uleb("Debug size");
      if (shape.bytes > 0) {
        shape.first_line = body.uleb("First line");
        shape.line_count = body.uleb("Line count");
      }
    }
    if (
      instructionCount * 4 + upvalueCount * 2 + gcCount + numberCount >
      body.remaining
    )
      throw malformed("Prototype counts exceed its declared length");
    this.charge(400 + upvalueCount * 8 + (gcCount + numberCount) * 48);
    const instructions = { offset: body.pos, bytes: instructionCount * 4 };
    body.take(instructions.bytes, "Instructions");
    const upvalueRefs = Array.from({ length: upvalueCount }, () => {
      const ref = body.take(2, "Upvalue reference");
      return this.header.flags.big_endian
        ? ref.readUInt16BE()
        : ref.readUInt16LE();
    });
    // Bytecode operands index GC constants backwards from their dump order.
    const gc = Array.from({ length: gcCount }, (_, position) =>
      this.gcConstant(body, gcCount - 1 - position),
    );
    const numbers = Array.from({ length: numberCount }, (_, index) =>
      this.numberConstant(body, index),
    );
    const debug =
      shape.bytes > 0
        ? this.debug(body, {
            ...shape,
            instructions: instructionCount,
            upvalues: upvalueCount,
          })
        : null;
    if (body.remaining !== 0)
      throw malformed("Prototype length does not match its contents");
    return {
      index: this.prototypes.length,
      location: { offset: start, bytes: length },
      flags: {
        raw: flags,
        has_child: (flags & 0x01) !== 0,
        vararg: (flags & 0x02) !== 0,
        ffi: (flags & 0x04) !== 0,
      },
      parameter_count: parameterCount,
      frame_size: frameSize,
      upvalue_refs: upvalueRefs,
      instruction_count: instructionCount,
      instructions,
      constants: { gc, numbers },
      debug,
    };
  }
}

/** Parse one LuaJIT 2.0/2.1 dump structurally; nothing is loaded or executed. */
export const readLuajitBytecode = (
  bytes: Buffer,
  outputBudget: number,
): Omit<LuajitBytecode, "artifact" | "limitations"> => {
  const { header, cursor } = readHeader(bytes);
  const decoder = new Decoder(bytes, header, outputBudget);
  for (;;) {
    const length = cursor.uleb("Prototype length");
    if (length === 0) break;
    if (length > cursor.remaining) throw malformed("Prototype is truncated");
    const prototype = decoder.prototype(cursor.pos, length);
    decoder.prototypes.push(prototype);
    decoder.unclaimed.push(prototype.index);
    cursor.pos += length;
  }
  const [main, ...extra] = decoder.unclaimed;
  if (main === undefined) throw malformed("Dump contains no prototype");
  if (extra.length > 0)
    throw malformed("Dump has prototypes that no parent references");
  return {
    header,
    prototypes: decoder.prototypes,
    main_prototype: main,
    trailing_bytes: cursor.remaining,
  };
};
