// Local model runtime: llama.cpp (CPU only) embedded via node-llama-cpp.
// - one model + one 2,048-token context, loaded once and reused
// - exact token counting with the model's own tokenizer and chat template
// - JSON-schema grammar so output is valid JSON by construction
// - hard per-call timeout via AbortSignal; one call at a time (mutex)
import fs from "node:fs";
import path from "node:path";
import { getLlama, LlamaChatSession, QwenChatWrapper, resolveChatWrapper } from "node-llama-cpp";
import { pathToFileURL } from "node:url";
import { CONFIG, MODELS, MODELS_DIR, ROOT_DIR } from "./config.js";

export class ModelTimeoutError extends Error {}

// The public createGrammarForJsonSchema() forces pretty-printed JSON (newlines +
// 4-space indents), which costs ~40% more output tokens. The internal generator
// supports compact output; load it by path, fall back to the public API.
let compactGbnf = null;
try {
  const p = path.join(ROOT_DIR, "node_modules/node-llama-cpp/dist/utils/gbnfJson/getGbnfGrammarForGbnfJsonSchema.js");
  compactGbnf = (await import(pathToFileURL(p).href)).getGbnfGrammarForGbnfJsonSchema;
} catch {
  /* fallback below */
}

class LocalLLM {
  constructor() {
    this.llama = null;
    this.model = null;
    this.context = null;
    this.sequence = null;
    this.modelInfo = null;
    this.loadMs = 0;
    this.loading = null;
    this.grammars = new Map();
    this.queue = Promise.resolve(); // serializes model calls
    this.stats = { calls: 0, failures: 0, timeouts: 0, totalMs: 0, promptTokens: 0, outputTokens: 0, maxContextUsed: 0 };
  }

  availableModels() {
    return MODELS.map((m) => ({
      id: m.id,
      label: m.label,
      file: m.file,
      downloaded: fs.existsSync(path.join(MODELS_DIR, m.file)),
      sizeMb: fs.existsSync(path.join(MODELS_DIR, m.file))
        ? Math.round(fs.statSync(path.join(MODELS_DIR, m.file)).size / 1e6)
        : null,
      active: this.modelInfo?.id === m.id,
    }));
  }

  get ready() {
    return !!this.context;
  }

  async load(modelId) {
    if (this.loading) await this.loading.catch(() => {});
    if (this.modelInfo?.id === modelId && this.ready) return;
    const info = MODELS.find((m) => m.id === modelId);
    if (!info) throw new Error(`Unknown model ${modelId}`);
    const modelPath = path.join(MODELS_DIR, info.file);
    if (!fs.existsSync(modelPath)) throw new Error(`Model file missing: ${info.file}. Run: npm run download-model -- ${info.id}`);
    // RAM guard: weights + ~0.9 GB (KV cache, compute buffers, Node) must fit the limit.
    const needMb = Math.round(fs.statSync(modelPath).size / 1048576) + 900;
    if (needMb > CONFIG.ramLimitMb) throw new Error(`Model needs ~${needMb} MB, over the ${CONFIG.ramLimitMb} MB RAM limit`);

    this.loading = (async () => {
      await this.unload();
      const t0 = Date.now();
      // build:"never" + skipDownload: never fetch or compile llama.cpp at runtime,
      // so the app is guaranteed offline after `npm install`. maxThreads caps all
      // llama.cpp threads to the 2 vCPU budget.
      this.llama ??= await getLlama({ gpu: false, build: "never", skipDownload: true, maxThreads: CONFIG.threads, logLevel: "error" });
      this.model = await this.llama.loadModel({ modelPath, gpuLayers: 0, useMmap: true });
      this.context = await this.model.createContext({
        contextSize: CONFIG.contextSize,
        sequences: 1,
        threads: CONFIG.threads,
        batchSize: 512,
      });
      this.sequence = this.context.getSequence();
      // Qwen3.5 thinks by default; hidden reasoning would consume the 2k budget
      // (and with a grammar it returned empty text). Disable it in the template.
      const auto = resolveChatWrapper(this.model);
      this.chatWrapper = auto?.wrapperName === "Qwen" ? new QwenChatWrapper({ thoughts: "discourage" }) : auto;
      this.grammars.clear();
      this.modelInfo = info;
      this.loadMs = Date.now() - t0;
    })();
    try {
      await this.loading;
    } finally {
      this.loading = null;
    }
  }

  async unload() {
    this.grammars.clear();
    await this.context?.dispose();
    await this.model?.dispose();
    this.context = this.model = this.sequence = this.modelInfo = null;
  }

  countTokens = (text) => this.model.tokenize(text).length;

  /** Exact prompt size including the chat template, as the model will see it. */
  promptTokens(system, user) {
    try {
      const session = new LlamaChatSession({ contextSequence: this.sequence, systemPrompt: system, autoDisposeSequence: false, chatWrapper: this.chatWrapper });
      const { contextText } = session.chatWrapper.generateContextState({
        chatHistory: [
          { type: "system", text: system },
          { type: "user", text: user },
          { type: "model", response: [] },
        ],
      });
      session.dispose({ disposeSequence: false });
      return contextText.tokenize(this.model.tokenizer).length;
    } catch {
      return this.countTokens(system) + this.countTokens(user) + CONFIG.safetyMarginTokens;
    }
  }

  async grammarFor(schema) {
    const key = JSON.stringify(schema);
    if (!this.grammars.has(key)) {
      let g;
      if (compactGbnf) {
        try {
          // Replace the generator's `"\n\n\n\n" [\n]*` terminator with a single
          // "\n" stop trigger so generation ends right after the JSON closes.
          // (Removing the terminator entirely makes generation never stop.)
          const gbnf = compactGbnf(schema, { allowNewLines: false, scopePadSpaces: 0 }).replace(/ "(\\n){4}" \[\\n\]\*/, ' "\\n"');
          g = await this.llama.createGrammar({ grammar: gbnf, stopGenerationTriggers: ["\n"], trimWhitespaceSuffix: true });
        } catch {
          g = null;
        }
      }
      this.grammars.set(key, g || (await this.llama.createGrammarForJsonSchema(schema)));
    }
    return this.grammars.get(key);
  }

  /**
   * Run one model call. Resolves { text, ms, promptTokens, outputTokens }.
   * Throws ModelTimeoutError on timeout; other errors propagate.
   */
  generateJson({ system, user, schema, maxTokens = CONFIG.maxOutputTokens, timeoutMs = CONFIG.callTimeoutMs, temperature = CONFIG.temperature }) {
    const run = async () => {
      if (!this.ready) throw new Error("Model not loaded");
      const promptTokens = this.promptTokens(system, user);
      if (promptTokens + maxTokens > CONFIG.contextSize) {
        throw new Error(`Token budget exceeded: prompt ${promptTokens} + output ${maxTokens} > ${CONFIG.contextSize}`);
      }
      const grammar = schema ? await this.grammarFor(schema) : undefined;
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(new ModelTimeoutError(`model call exceeded ${timeoutMs} ms`)), timeoutMs);
      const t0 = Date.now();
      const session = new LlamaChatSession({ contextSequence: this.sequence, systemPrompt: system, autoDisposeSequence: false, chatWrapper: this.chatWrapper });
      this.stats.calls++;
      try {
        const text = await session.prompt(user, {
          grammar,
          maxTokens,
          temperature,
          signal: ac.signal,
          budgets: { thoughtTokens: 0 }, // no hidden reasoning: it would eat the 2k budget
        });
        const used = this.sequence.contextTokens.length;
        const outputTokens = Math.max(0, used - promptTokens);
        const ms = Date.now() - t0;
        this.stats.totalMs += ms;
        this.stats.promptTokens += promptTokens;
        this.stats.outputTokens += outputTokens;
        this.stats.maxContextUsed = Math.max(this.stats.maxContextUsed, used);
        return { text, ms, promptTokens, outputTokens, contextUsed: used };
      } catch (err) {
        this.stats.failures++;
        if (ac.signal.aborted) {
          this.stats.timeouts++;
          throw ac.signal.reason instanceof ModelTimeoutError ? ac.signal.reason : new ModelTimeoutError("model call aborted");
        }
        throw err;
      } finally {
        clearTimeout(timer);
        session.dispose({ disposeSequence: false });
        await this.sequence.clearHistory().catch(() => {}); // fresh context for every call
      }
    };
    const p = this.queue.then(run, run);
    this.queue = p.catch(() => {});
    return p;
  }

  status() {
    const s = this.stats;
    return {
      ready: this.ready,
      model: this.modelInfo ? { id: this.modelInfo.id, label: this.modelInfo.label, file: this.modelInfo.file } : null,
      loadMs: this.loadMs,
      threads: CONFIG.threads,
      contextSize: CONFIG.contextSize,
      calls: s.calls,
      failures: s.failures,
      timeouts: s.timeouts,
      avgCallMs: s.calls - s.failures > 0 ? Math.round(s.totalMs / (s.calls - s.failures)) : null,
      avgPromptTokens: s.calls - s.failures > 0 ? Math.round(s.promptTokens / (s.calls - s.failures)) : null,
      avgOutputTokens: s.calls - s.failures > 0 ? Math.round(s.outputTokens / (s.calls - s.failures)) : null,
      maxContextUsed: s.maxContextUsed,
    };
  }
}

export const llm = new LocalLLM();
