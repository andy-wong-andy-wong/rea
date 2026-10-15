import { symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { LuajitBytecodeProvider } from "../../../src/luajit/LuajitBytecodeProvider.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../../../src/domain/analysisErrorCore.js";
import {
  luajitGolden,
  luajitNilTableDump,
} from "../../fixtures/luajit/bytecode.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const inspect = async (name: string, bytes: Buffer, signal?: AbortSignal) => {
  const root = await createTestTempDirectory("rea-luajit-provider-");
  const path = join(root, name);
  await writeFile(path, bytes);
  const provider = new LuajitBytecodeProvider();
  try {
    return { path, result: await provider.inspect({ path }, signal ? { signal } : {}) };
  } finally {
    await provider.close();
  }
};

it("reports file identity and exact ranges for a real dump", async () => {
  const bytes = luajitGolden("debug");
  const { path, result } = await inspect("sample.luac", bytes);
  if (!result.ok) throw result.error;
  expect(result.value.artifact).toMatchObject({ path, bytes: bytes.length });
  expect(result.value.artifact.sha256).toMatch(/^[0-9a-f]{64}$/u);
  expect(result.value.main_prototype).toBe(1);
  const [first] = result.value.prototypes;
  const last = result.value.prototypes.at(-1)!;
  // One length byte follows the header; the terminator follows the last prototype.
  expect(first?.location.offset).toBe(result.value.header.bytes + 1);
  expect(last.location.offset + last.location.bytes).toBe(bytes.length - 1);
  expect(result.value.limitations).not.toContainEqual(
    expect.stringMatching(/stripped/u),
  );
});

it("states that stripped dumps lack debug names", async () => {
  const { result } = await inspect("stripped.luac", luajitGolden("stripped"));
  if (!result.ok) throw result.error;
  expect(result.value.limitations).toContainEqual(
    expect.stringMatching(/stripped debug information/u),
  );
});

it("distinguishes unsupported files from damaged dumps", async () => {
  const puc = await inspect("puc.luac", Buffer.from("\x1bLuaQ\x00", "latin1"));
  expect(!puc.result.ok && puc.result.error).toBeInstanceOf(
    AnalysisUnsupportedTargetError,
  );
  const damaged = await inspect(
    "damaged.luac",
    luajitGolden("debug").subarray(0, 40),
  );
  if (damaged.result.ok) throw new Error("A truncated dump must not succeed");
  expect(damaged.result.error).toBeInstanceOf(AnalysisInputError);
  expect(damaged.result.error).toMatchObject({
    issues: [expect.objectContaining({ reason: "invalid_format" })],
  });
});

it("fails closed when a small file would expand beyond the output budget", async () => {
  const { path, result } = await inspect(
    "expansion.luac",
    luajitNilTableDump(300_000),
  );
  if (result.ok) throw new Error("Oversized structure must not succeed");
  expect(result.error).toBeInstanceOf(AnalysisResourceConstraintError);
  expect(result.error).toMatchObject({
    reportedLimits: { maximum_output_bytes: 8 * 1024 * 1024 },
    reason: expect.stringContaining(path),
  });
});

it("reports cancellation instead of a partial result", async () => {
  const controller = new AbortController();
  controller.abort();
  const { result } = await inspect(
    "cancelled.luac",
    luajitGolden("stripped"),
    controller.signal,
  );
  expect(!result.ok && result.error).toBeInstanceOf(AnalysisCancelledError);
});

it("rejects a missing file and a symlink as input errors", async () => {
  const root = await createTestTempDirectory("rea-luajit-path-");
  const provider = new LuajitBytecodeProvider();
  const missing = await provider.inspect({ path: join(root, "absent.luac") });
  expect(!missing.ok && missing.error).toBeInstanceOf(AnalysisInputError);
  if (process.platform !== "win32") {
    const original = join(root, "original.luac");
    const link = join(root, "link.luac");
    await writeFile(original, luajitGolden("stripped"));
    await symlink(original, link);
    const linked = await provider.inspect({ path: link });
    expect(!linked.ok && linked.error).toBeInstanceOf(AnalysisInputError);
  }
  await provider.close();
});
