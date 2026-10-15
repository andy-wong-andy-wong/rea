import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  InspectLuajitBytecodeInput,
  LuajitBytecode,
} from "../../domain/luajit/luajitBytecode.js";
import type { Result } from "../../domain/result.js";

/** Replaceable offline bytecode reader with no target-execution authority. */
export interface LuajitBytecodePort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  inspect(
    input: InspectLuajitBytecodeInput,
    options?: ExecutionOptions,
  ): Promise<Result<LuajitBytecode, AnalysisError>>;
}
