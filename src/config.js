// Central configuration. Every limit from the brief lives here so the token
// budget and resource plan can be read (and changed) in one place.
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const env = (k, d) => (process.env[k] !== undefined ? process.env[k] : d);
const num = (k, d) => Number(env(k, d));

export const ROOT_DIR = ROOT;
export const MODELS_DIR = path.join(ROOT, "models");
export const DATA_DIR = path.join(ROOT, "data");
export const UPLOAD_DIR = path.join(DATA_DIR, "uploads");
export const JOBS_DIR = path.join(DATA_DIR, "jobs");

// Supported local models (text-only GGUF, no vision projector is loaded).
export const MODELS = [
  {
    id: "qwen3.5-2b",
    label: "Qwen3.5 2B (Q4_K_M)",
    file: "Qwen3.5-2B-Q4_K_M.gguf",
    url: "https://huggingface.co/unsloth/Qwen3.5-2B-GGUF/resolve/main/Qwen3.5-2B-Q4_K_M.gguf",
  },
  {
    id: "qwen3.5-0.8b",
    label: "Qwen3.5 0.8B (Q4_K_M)",
    file: "Qwen3.5-0.8B-Q4_K_M.gguf",
    url: "https://huggingface.co/unsloth/Qwen3.5-0.8B-GGUF/resolve/main/Qwen3.5-0.8B-Q4_K_M.gguf",
  },
];
export const DEFAULT_MODEL_ID = env("MODEL_ID", "qwen3.5-2b");

export const CONFIG = {
  port: num("PORT", 3000),

  // --- Hardware limits (brief: 2 vCPU, no GPU, 4 GB RAM total) ---
  threads: num("LLM_THREADS", 2),
  gpu: false,
  ramLimitMb: num("RAM_LIMIT_MB", 4096),

  // --- Token budget (brief: 2,048 tokens per call, everything included) ---
  contextSize: 2048,
  maxOutputTokens: num("MAX_OUTPUT_TOKENS", 400), // reserved for the JSON reply
  maxMemoryTokens: num("MAX_MEMORY_TOKENS", 260), // carried context from earlier chunks
  safetyMarginTokens: 48, // chat-template overhead / tokenizer drift
  // Log budget per chunk = contextSize - fixedPrompt - maxMemory - maxOutput - safety
  // (computed at runtime from the real tokenizer, see analyzer.js).

  // --- Reliability ---
  callTimeoutMs: num("CALL_TIMEOUT_MS", 180_000),
  maxRetries: num("MAX_RETRIES", 2),
  temperature: 0.1,

  // --- Uploads ---
  maxUploadBytes: num("MAX_UPLOAD_MB", 25) * 1024 * 1024,
  allowedExtensions: [".log", ".txt"],
  maxLineChars: 600, // a single absurdly long line is truncated before tokenizing
};
