import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { LuajitBytecodePort } from "../application/luajit/LuajitBytecodePort.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import {
  luajitBytecodeSchema,
  type InspectLuajitBytecodeInput,
  type LuajitBytecode,
} from "../domain/luajit/luajitBytecode.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  LuajitFormatFailure,
  LuajitResourceFailure,
  readLuajitBytecode,
} from "./LuajitBytecodeReader.js";

/** Bundled format reader identity; the dump version is a separate observed fact. */
export const LUAJIT_PROVIDER_IDENTITY = {
  id: "luajit-bytecode",
  name: "REA LuaJIT bytecode reader",
  version: "1",
} as const;
const OPERATION = "inspect_luajit_bytecode";
const INPUT_BYTES = 64 * 1024 * 1024;
const OUTPUT_BYTES = 8 * 1024 * 1024;

const failureForPrimary = (
  cause: unknown,
  path: string,
  signal?: AbortSignal,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, cause.message, {
      cause,
    });
  if (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled")
    return new AnalysisCancelledError(OPERATION, { cause });
  if (signal?.aborted) return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof LuajitResourceFailure) return outputLimit(path, cause);
  if (cause instanceof LuajitFormatFailure)
    return cause.kind === "unsupported"
      ? new AnalysisUnsupportedTargetError(OPERATION, path, cause.message, {
          cause,
        })
      : new AnalysisInputError(OPERATION, { cause }, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: `Selected artifact ${path}: ${cause.message}`,
          },
        ]);
  if (cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "limit")
      return new AnalysisResourceConstraintError(
        OPERATION,
        "file-size",
        cause.message,
        { maximum_input_bytes: INPUT_BYTES },
        { cause },
      );
    if (cause.reason === "path")
      return new AnalysisInputError(OPERATION, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
  }
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
        cause,
      });
    if (
      ["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(
        String(cause.code),
      )
    )
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected artifact could not be read (${String(cause.code)}): ${path}.`,
        },
      ]);
  }
  return new ProviderAdapterError(LUAJIT_PROVIDER_IDENTITY.id, OPERATION, {
    cause,
    diagnostics: {
      path,
      reason: cause instanceof Error ? cause.message : String(cause),
    },
  });
};

const failureFor = (
  cause: unknown,
  path: string,
  signal?: AbortSignal,
): AnalysisError => {
  const primary = failureForPrimary(cause, path, signal);
  if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined)
    return primary;
  const cleanup = new ProviderCleanupError(
    LUAJIT_PROVIDER_IDENTITY.id,
    cause.cleanup.resources,
    { reason: cause.cleanup.reason },
    { operation: OPERATION, cause },
  );
  return analysisErrorWithCleanupFailure(primary, cleanup, OPERATION);
};

const outputLimit = (path: string, cause?: unknown) =>
  new AnalysisResourceConstraintError(
    OPERATION,
    "transport",
    `Complete LuaJIT structure for ${path} exceeds the inline output budget; no partial success is returned.`,
    { maximum_output_bytes: OUTPUT_BYTES },
    cause === undefined ? undefined : { cause },
  );

const limitationsFor = (
  dump: ReturnType<typeof readLuajitBytecode>,
): string[] => [
  "Bytecode structure is observed file content, not proof of the source program, its behavior or the toolchain that produced it.",
  "Instruction words are located by file range but not decoded; control flow, constant uses and calls are not recovered, and per-instruction line numbers are not decoded.",
  "Only LuaJIT 2.0/2.1 dumps are read; PUC-Lua bytecode is unsupported. The dump is never loaded or executed.",
  "Resource guards bound stable artifact reads to 64 MiB and complete decoded structure to 8 MiB; these are not operating-system memory or CPU limits.",
  ...(dump.header.flags.stripped
    ? [
        "The producer stripped debug information; chunk name, line ranges, upvalue names and variable names are unavailable.",
      ]
    : []),
  ...(dump.prototypes.some(
    (prototype) =>
      prototype.debug !== null &&
      (prototype.debug.upvalue_names === null ||
        prototype.debug.variables === null),
  )
    ? [
        "Some debug blocks do not follow the expected layout; their names are null while line ranges and sizes are preserved.",
      ]
    : []),
  ...(dump.trailing_bytes > 0
    ? [
        `${dump.trailing_bytes} bytes follow the dump terminator and are not interpreted.`,
      ]
    : []),
];

/** Stable in-process structural inspection without subprocesses, temporary files or a LuaJIT installation. */
export class LuajitBytecodeProvider implements LuajitBytecodePort {
  readonly identity = LUAJIT_PROVIDER_IDENTITY;
  readonly #resources = new ArtifactResourceScope();

  close(): Promise<void> {
    return this.#resources.close();
  }

  /** Read the complete dump structure while preserving original byte identity and file ranges. */
  async inspect(
    input: InspectLuajitBytecodeInput,
    options?: ExecutionOptions,
  ): Promise<Result<LuajitBytecode, AnalysisError>> {
    try {
      const snapshot = await this.#resources.run(() =>
        readStableArtifact(
          input.path,
          INPUT_BYTES,
          options?.signal,
          undefined,
          this.#resources,
        ),
      );
      options?.signal?.throwIfAborted();
      const dump = readLuajitBytecode(snapshot.bytes, OUTPUT_BYTES);
      const report = {
        artifact: {
          path: input.path,
          sha256: snapshot.sha256,
          bytes: snapshot.bytes.length,
        },
        ...dump,
        limitations: limitationsFor(dump),
      };
      if (Buffer.byteLength(JSON.stringify(report), "utf8") > OUTPUT_BYTES)
        throw outputLimit(input.path);
      const parsed = luajitBytecodeSchema.safeParse(report);
      if (!parsed.success)
        throw new AnalysisOutputError(
          OPERATION,
          "LuaJIT reader produced invalid source ranges or report values.",
          { cause: parsed.error },
        );
      options?.signal?.throwIfAborted();
      return ok(parsed.data);
    } catch (cause: unknown) {
      return err(failureFor(cause, input.path, options?.signal));
    }
  }
}
