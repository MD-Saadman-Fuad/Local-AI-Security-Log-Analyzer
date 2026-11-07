// Smoke test: load the model, plan the sample log, run ONE part through the model.
import { llm } from "../src/llm.js";
import { CONFIG, DEFAULT_MODEL_ID } from "../src/config.js";
import { planChunks, loadChunkLines, formatLine } from "../src/chunker.js";
import { SYSTEM_PROMPT, CHUNK_SCHEMA, chunkUserPrompt } from "../src/prompts.js";
import { parseModelJson } from "../src/jsonRepair.js";

const file = process.argv[2];
const modelId = process.argv[3] || DEFAULT_MODEL_ID;
const part = Number(process.argv[4] || 0);
await llm.load(modelId);
console.log(`loaded ${modelId} in ${llm.loadMs} ms, RSS ${Math.round(process.memoryUsage().rss / 1048576)} MB`);
const fixed = llm.promptTokens(SYSTEM_PROMPT, chunkUserPrompt({ partNo: 99, partCount: 99, startLine: 99999, endLine: 99999, memory: "", logText: "" }));
const budget = CONFIG.contextSize - fixed - CONFIG.maxMemoryTokens - CONFIG.maxOutputTokens - CONFIG.safetyMarginTokens;
const plan = await planChunks(file, llm.countTokens, budget);
console.log(`fixed prompt ${fixed} tok, log budget ${budget}; ${plan.chunks.length} parts; compact ${plan.compactTokens} tok; raw tokens (first 200 lines) ${plan.rawTokensSample}`);
const c = plan.chunks[part];
const lines = await loadChunkLines(file, c);
const user = chunkUserPrompt({ partNo: part + 1, partCount: plan.chunks.length, startLine: c.startLine, endLine: c.endLine, memory: "", logText: lines.map((l) => formatLine(l.lineNo, l.text)).join("\n") });
const res = await llm.generateJson({ system: SYSTEM_PROMPT, user, schema: CHUNK_SCHEMA });
console.log(`call: ${res.ms} ms, prompt ${res.promptTokens}, out ${res.outputTokens}, ctx ${res.contextUsed}, RSS ${Math.round(process.memoryUsage().rss / 1048576)} MB`);
console.log(res.text);
console.log(JSON.stringify(parseModelJson(res.text).ok));
await llm.unload();
