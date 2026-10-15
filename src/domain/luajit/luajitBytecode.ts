import { z } from "zod";
import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";
import { CANONICAL_BASE64_PATTERN } from "../stringPatterns.js";

const countSchema = z.number().int().nonnegative();
const base64Schema = z.string().regex(CANONICAL_BASE64_PATTERN);
const doubleBitsSchema = z.string().regex(/^0x[0-9a-f]{16}$/u);

/** Exact UTF-8 text, or the original bytes when they do not decode exactly. */
export const luajitTextSchema = z.union([
  z.strictObject({ text: z.string() }),
  z.strictObject({ text: z.null(), bytes_base64: base64Schema }),
]);

/** IEEE-754 bits are the source value; `value` is null for NaN and infinities. */
const luajitDoubleSchema = z.strictObject({
  bits: doubleBitsSchema,
  value: z.number().nullable(),
});

const tableValueSchema = z.union([
  z.strictObject({ kind: z.literal("nil") }),
  z.strictObject({ kind: z.literal("boolean"), value: z.boolean() }),
  z.strictObject({ kind: z.literal("integer"), value: z.number().int() }),
  luajitDoubleSchema.extend({ kind: z.literal("number") }),
  z.strictObject({ kind: z.literal("string"), text: z.string() }),
  z.strictObject({
    kind: z.literal("string"),
    text: z.null(),
    bytes_base64: base64Schema,
  }),
]);

/** One GC constant, indexed by the operand value bytecode uses to reference it. */
const gcConstantSchema = z.union([
  z.strictObject({
    index: countSchema,
    kind: z.literal("child"),
    prototype: countSchema,
  }),
  z.strictObject({
    index: countSchema,
    kind: z.literal("table"),
    array: z.array(tableValueSchema),
    hash: z.array(
      z.strictObject({ key: tableValueSchema, value: tableValueSchema }),
    ),
  }),
  z.strictObject({
    index: countSchema,
    kind: z.enum(["int64", "uint64"]),
    value: z.string().regex(/^-?\d+$/u),
  }),
  z.strictObject({
    index: countSchema,
    kind: z.literal("complex"),
    real: luajitDoubleSchema,
    imaginary: luajitDoubleSchema,
  }),
  z.strictObject({
    index: countSchema,
    kind: z.literal("string"),
    text: z.string(),
  }),
  z.strictObject({
    index: countSchema,
    kind: z.literal("string"),
    text: z.null(),
    bytes_base64: base64Schema,
  }),
]);

const numberConstantSchema = z.union([
  z.strictObject({
    index: countSchema,
    kind: z.literal("integer"),
    value: z.number().int(),
  }),
  luajitDoubleSchema.extend({
    index: countSchema,
    kind: z.literal("number"),
  }),
]);

const sourceRangeSchema = z.strictObject({
  offset: countSchema,
  bytes: countSchema,
});

/** Debug facts are null when the producer omitted them or their layout is unreadable. */
const debugSchema = z.strictObject({
  bytes: countSchema,
  first_line: countSchema,
  line_count: countSchema,
  line_info_entry_bytes: z.union([z.literal(1), z.literal(2), z.literal(4)]),
  upvalue_names: z.array(luajitTextSchema).nullable(),
  variables: z
    .array(
      z.strictObject({
        name: luajitTextSchema,
        builtin: z.boolean(),
        start_pc: countSchema,
        end_pc: countSchema,
      }),
    )
    .nullable(),
});

const prototypeSchema = z.strictObject({
  index: countSchema,
  location: sourceRangeSchema,
  flags: z.strictObject({
    raw: z.number().int().min(0).max(255),
    has_child: z.boolean(),
    vararg: z.boolean(),
    ffi: z.boolean(),
  }),
  parameter_count: z.number().int().min(0).max(255),
  frame_size: z.number().int().min(0).max(255),
  upvalue_refs: z.array(z.number().int().min(0).max(0xffff)),
  instruction_count: countSchema,
  instructions: sourceRangeSchema,
  constants: z.strictObject({
    gc: z.array(gcConstantSchema),
    numbers: z.array(numberConstantSchema),
  }),
  debug: debugSchema.nullable(),
});

/** One exact local artifact, independent of any active disassembler target. */
export const inspectLuajitBytecodeInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to a LuaJIT bytecode file",
  ),
});

/** Complete structural observation of one LuaJIT bytecode dump; no instructions are decoded. */
export const luajitBytecodeSchema = z
  .strictObject({
    artifact: z.strictObject({
      path: localPathStringSchema,
      sha256: digestSchema,
      bytes: countSchema,
    }),
    header: z.strictObject({
      version: z.number().int().min(0).max(255),
      flags: z.strictObject({
        raw: countSchema,
        big_endian: z.boolean(),
        stripped: z.boolean(),
        ffi: z.boolean(),
        fr2: z.boolean(),
      }),
      chunk_name: luajitTextSchema.nullable(),
      bytes: countSchema,
    }),
    prototypes: z.array(prototypeSchema),
    main_prototype: countSchema,
    trailing_bytes: countSchema,
    limitations: z.array(z.string()),
  })
  .superRefine((report, context) => {
    const size = report.artifact.bytes;
    const inFile = (range: { offset: number; bytes: number }) =>
      range.offset <= size && range.bytes <= size - range.offset;
    if (report.header.bytes > size)
      context.addIssue({
        code: "custom",
        path: ["header", "bytes"],
        message: "Header is outside the selected artifact.",
      });
    report.prototypes.forEach((prototype, index) => {
      for (const field of ["location", "instructions"] as const)
        if (!inFile(prototype[field]))
          context.addIssue({
            code: "custom",
            path: ["prototypes", index, field],
            message: "Source range is outside the selected artifact.",
          });
    });
    if (report.main_prototype >= report.prototypes.length)
      context.addIssue({
        code: "custom",
        path: ["main_prototype"],
        message: "Main prototype is not in the prototype list.",
      });
  });

export type LuajitBytecode = z.infer<typeof luajitBytecodeSchema>;
export type InspectLuajitBytecodeInput = z.infer<
  typeof inspectLuajitBytecodeInputSchema
>;
