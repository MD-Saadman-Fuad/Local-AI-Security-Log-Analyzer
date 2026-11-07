// Job orchestration: plan -> per-part model calls -> validate/merge -> correlate -> report.
// One job and one model call at a time keeps RAM flat (single 2k context).
// Job state is checkpointed to disk after every part, so completed findings
// survive crashes and a restarted server resumes unfinished jobs.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { CONFIG, JOBS_DIR } from "./config.js";
import { llm, ModelTimeoutError } from "./llm.js";
import { planChunks, loadChunkLines, formatLine } from "./chunker.js";
import { Ledger } from "./ledger.js";
import { parseModelJson } from "./jsonRepair.js";
import { validateFindings, FindingStore, correlate, hydrateEvidence, buildReport, fallbackSummary } from "./aggregate.js";
import { SYSTEM_PROMPT, CHUNK_SCHEMA, chunkUserPrompt, SUMMARY_SCHEMA, SUMMARY_SYSTEM_PROMPT, summaryUserPrompt } from "./prompts.js";

const jobs = new Map();
const queue = [];
let working = false;

const rssMb = () => Math.round(process.memoryUsage().rss / 1048576);

function persist(job) {
  fs.mkdirSync(JOBS_DIR, { recursive: true });
  const file = path.join(JOBS_DIR, `${job.id}.json`);
  const { _ledger, _store, cancelRequested, ...plain } = job;
  plain.ledger = _ledger?.toJSON();
  plain.store = _store?.toJSON();
  fs.writeFileSync(file + ".tmp", JSON.stringify(plain));
  fs.renameSync(file + ".tmp", file); // atomic replace: never a half-written checkpoint
}

function log(job, msg, level = "info") {
  job.events.push({ t: new Date().toISOString(), level, msg });
  if (job.events.length > 200) job.events.splice(0, job.events.length - 200);
}

export function createJob({ filePath, fileName, size, modelId }) {
  const job = {
    id: crypto.randomUUID().slice(0, 8),
    fileName,
    filePath,
    size,
    modelId,
    status: "queued",
    createdAt: new Date().toISOString(),
    startedAt: null,
    finishedAt: null,
    plan: null,
    events: [],
    rejected: [],
    report: null,
    error: null,
    _ledger: new Ledger(),
    _store: new FindingStore(),
  };
  jobs.set(job.id, job);
  log(job, `Queued ${fileName} (${(size / 1024).toFixed(1)} KB) with model ${modelId}`);
  persist(job);
  queue.push(job.id);
  kick();
  return job;
}

export function getJob(id) {
  return jobs.get(id);
}
export function listJobs() {
  return [...jobs.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}
export function cancelJob(id) {
  const job = jobs.get(id);
  if (!job) return false;
  if (job.status === "queued") {
    job.status = "cancelled";
    queue.splice(queue.indexOf(id), 1);
    persist(job);
  } else job.cancelRequested = true;
  return true;
}
export const isBusy = () => working || queue.length > 0;

/** Public view of a job (no internal objects). */
export function jobView(job, { full = false } = {}) {
  const chunks = job.plan?.chunks || [];
  const done = chunks.filter((c) => c.status === "done" || c.status === "failed").length;
  const v = {
    id: job.id,
    fileName: job.fileName,
    size: job.size,
    modelId: job.modelId,
    status: job.status,
    createdAt: job.createdAt,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    error: job.error,
    progress: { partsDone: done, partsTotal: chunks.length, pct: chunks.length ? Math.round((done / chunks.length) * 100) : 0 },
    findingsSoFar: job._store ? job._store.all().length : 0,
    events: job.events.slice(-40),
  };
  if (full) {
    v.plan = job.plan;
    v.rejected = job.rejected.slice(-50);
  }
  return v;
}

async function kick() {
  if (working) return;
  working = true;
  try {
    while (queue.length) {
      const job = jobs.get(queue.shift());
      if (!job || job.status === "cancelled") continue;
      try {
        await runJob(job);
      } catch (err) {
        job.status = "failed";
        job.error = err.message;
        log(job, `Job failed: ${err.message}`, "error");
      }
      job.finishedAt = new Date().toISOString();
      persist(job);
    }
  } finally {
    working = false;
  }
}

async function runJob(job) {
  job.startedAt ??= new Date().toISOString();
  if (!fs.existsSync(job.filePath)) throw new Error("uploaded file no longer exists");
  if (!llm.ready || llm.modelInfo?.id !== job.modelId) {
    log(job, `Loading model ${job.modelId}…`);
    await llm.load(job.modelId);
    log(job, `Model loaded in ${llm.loadMs} ms (RSS ${rssMb()} MB)`);
  }
  const count = llm.countTokens;

  if (!job.plan) {
    job.status = "planning";
    // Fixed cost of every call = system prompt + template + user scaffolding.
    const fixed = llm.promptTokens(SYSTEM_PROMPT, chunkUserPrompt({ partNo: 99, partCount: 99, startLine: 99999, endLine: 99999, memory: "", logText: "" }));
    const logBudget = CONFIG.contextSize - fixed - CONFIG.maxMemoryTokens - CONFIG.maxOutputTokens - CONFIG.safetyMarginTokens;
    if (logBudget < 200) throw new Error(`token budget too small for log text (${logBudget})`);
    const p = await planChunks(job.filePath, count, logBudget);
    if (!p.chunks.length) throw new Error("file contains no log lines");
    job.plan = {
      budget: {
        context: CONFIG.contextSize,
        fixedPrompt: fixed,
        memory: CONFIG.maxMemoryTokens,
        output: CONFIG.maxOutputTokens,
        safety: CONFIG.safetyMarginTokens,
        logPerPart: logBudget,
      },
      totalLines: p.totalLines,
      compactTokens: p.compactTokens,
      rawTokensSample: p.rawTokensSample,
      chunks: p.chunks.map((c) => ({ ...c, status: "pending", attempts: 0 })),
    };
    log(job, `Planned ${p.chunks.length} parts for ${p.totalLines} lines (${p.compactTokens} compact tokens, ≤${logBudget} log tokens per part)`);
    persist(job);
  } else {
    for (const c of job.plan.chunks) if (c.status === "running") c.status = "pending";
    log(job, `Resuming: ${job.plan.chunks.filter((c) => c.status === "pending").length} parts left`);
  }

  job.status = "running";
  const chunks = job.plan.chunks;
  for (const chunk of chunks) {
    if (job.cancelRequested) {
      job.status = "cancelled";
      log(job, "Cancelled by user; findings so far are kept", "warn");
      return finalize(job, { partial: true });
    }
    if (chunk.status !== "pending") continue;
    chunk.status = "running";
    await processChunk(job, chunk, chunks.length);
    persist(job);
  }
  await finalize(job, { partial: false });
}

async function callModelForLines(job, chunk, partCount, lines, label) {
  const count = llm.countTokens;
  const ips = new Set(lines.map((l) => l.facts.ip).filter(Boolean));
  const logText = lines.map((l) => formatLine(l.lineNo, l.text)).join("\n");
  const base = { partNo: chunk.index + 1, partCount, startLine: lines[0].lineNo, endLine: lines[lines.length - 1].lineNo, logText };

  // Fit memory into whatever budget is left after the exact prompt size.
  let memBudget = CONFIG.maxMemoryTokens;
  let mem, user, promptTokens;
  for (;;) {
    mem = job._ledger.render(ips, count, memBudget);
    user = chunkUserPrompt({ ...base, memory: mem.text });
    promptTokens = llm.promptTokens(SYSTEM_PROMPT, user);
    const over = promptTokens + CONFIG.maxOutputTokens - CONFIG.contextSize;
    if (over <= 0 || memBudget <= 0) break;
    memBudget = Math.max(0, memBudget - over - 8);
  }

  let lastErr;
  for (let attempt = 1; attempt <= CONFIG.maxRetries + 1; attempt++) {
    if (job.cancelRequested) throw new Error("cancelled");
    chunk.attempts++;
    try {
      const res = await llm.generateJson({
        system: SYSTEM_PROMPT,
        user,
        schema: CHUNK_SCHEMA,
        temperature: CONFIG.temperature + 0.2 * (attempt - 1), // vary output on retry
      });
      const parsed = parseModelJson(res.text);
      if (!parsed.ok) throw new Error(`unparseable JSON: ${parsed.error}`);
      const findings = Array.isArray(parsed.value?.findings) ? parsed.value.findings : [];
      chunk.metrics = {
        ms: res.ms,
        promptTokens: res.promptTokens,
        outputTokens: res.outputTokens,
        contextUsed: res.contextUsed,
        memoryTokens: mem.tokens,
        memoryEntities: mem.entities,
        repairedJson: !!parsed.repaired,
        rssMb: rssMb(),
      };
      log(job, `Part ${chunk.index + 1}${label}: ${findings.length} raw findings in ${(res.ms / 1000).toFixed(1)}s (prompt ${res.promptTokens} + out ${res.outputTokens} = ${res.contextUsed}/${CONFIG.contextSize} tok, memory ${mem.entities} entities)${parsed.repaired ? " [JSON repaired]" : ""}`);
      return findings;
    } catch (err) {
      lastErr = err;
      const kind = err instanceof ModelTimeoutError ? "timeout" : "error";
      log(job, `Part ${chunk.index + 1}${label} attempt ${attempt} ${kind}: ${err.message}`, "warn");
    }
  }
  throw lastErr;
}

async function processChunk(job, chunk, partCount) {
  const lines = await loadChunkLines(job.filePath, chunk, llm.countTokens, job.plan.budget.logPerPart);
  if (!lines.length) {
    chunk.status = "done";
    return;
  }
  let rawFindings = [];
  try {
    rawFindings = await callModelForLines(job, chunk, partCount, lines, "");
    chunk.status = "done";
  } catch (err) {
    if (err.message === "cancelled") {
      chunk.status = "pending";
      return;
    }
    // Retry safely with smaller inputs: split the part in half (shorter prompt and output).
    if (lines.length > 1) {
      log(job, `Part ${chunk.index + 1}: splitting into halves after repeated failures`, "warn");
      const mid = Math.ceil(lines.length / 2);
      let ok = 0;
      for (const [half, label] of [[lines.slice(0, mid), " (1st half)"], [lines.slice(mid), " (2nd half)"]]) {
        try {
          rawFindings.push(...(await callModelForLines(job, chunk, partCount, half, label)));
          ok++;
        } catch (e2) {
          log(job, `Part ${chunk.index + 1}${label} failed: ${e2.message}`, "error");
        }
      }
      chunk.status = ok ? "done" : "failed";
      if (ok < 2) chunk.error = "some lines could not be analyzed by the model";
    } else {
      chunk.status = "failed";
      chunk.error = err.message;
    }
  }

  // Facts are recorded even when the model call failed, so cross-part
  // correlation still sees these lines.
  job._ledger.ingest(chunk.index, lines);
  const { accepted, rejected } = validateFindings(rawFindings, lines, job._ledger);
  for (const f of accepted) {
    job._store.add(f, chunk.index, "model");
    job._ledger.flag(f.entity, f.attack_type, f.severity);
  }
  for (const r of rejected) job.rejected.push({ part: chunk.index + 1, why: r.why, finding: r.finding });
  if (rejected.length) log(job, `Part ${chunk.index + 1}: rejected ${rejected.length} finding(s) not supported by the evidence`, "warn");
}

async function finalize(job, { partial }) {
  const chunks = job.plan?.chunks || [];
  const chunkOfLine = (n) => {
    const c = chunks.find((c) => n >= c.startLine && n <= c.endLine);
    return c ? c.index : 0;
  };
  correlate(job._store, job._ledger, chunkOfLine);
  await hydrateEvidence(job._store, job.filePath);
  const report = buildReport(job._store, job._ledger, chunkOfLine);

  // One last model call: executive summary over the merged findings.
  report.summary = fallbackSummary(report);
  report.top_priorities = [];
  report.summary_source = "template";
  if (report.findings.length && llm.ready && !job.cancelRequested) {
    try {
      const outTok = 220;
      const sysTok = llm.promptTokens(SUMMARY_SYSTEM_PROMPT, summaryUserPrompt(""));
      let lines = [];
      let used = 0;
      for (const f of report.findings) {
        const ev = f.evidence_lines.length > 4 ? `L${f.first_line}…L${f.last_line} (${f.evidence_lines.length} lines)` : f.evidence_lines.map((n) => `L${n}`).join(",");
        const s = `- ${f.severity} | ${f.attack_type} | ${f.entity} | ${ev} | ${f.reason.slice(0, 140)}`;
        const t = llm.countTokens(s) + 1;
        if (sysTok + used + t + outTok + CONFIG.safetyMarginTokens > CONFIG.contextSize) break;
        lines.push(s);
        used += t;
      }
      const res = await llm.generateJson({ system: SUMMARY_SYSTEM_PROMPT, user: summaryUserPrompt(lines.join("\n")), schema: SUMMARY_SCHEMA, maxTokens: outTok, temperature: 0 });
      const parsed = parseModelJson(res.text);
      if (parsed.ok && parsed.value.summary) {
        // The schema caps length, which can cut mid-sentence: keep whole sentences only.
        const s = String(parsed.value.summary).trim();
        const end = s.lastIndexOf(". ");
        report.summary = /[.!?]$/.test(s) || end < 0 ? s : s.slice(0, end + 1);
        report.top_priorities = Array.isArray(parsed.value.top_priorities) ? parsed.value.top_priorities : [];
        report.summary_source = "model";
      }
      log(job, `Summary written by model in ${(res.ms / 1000).toFixed(1)}s`);
    } catch (err) {
      log(job, `Summary call failed (${err.message}); using template summary`, "warn");
    }
  }

  const failed = chunks.filter((c) => c.status === "failed");
  const metrics = chunks.map((c) => c.metrics).filter(Boolean);
  report.meta = {
    file: job.fileName,
    model: job.modelId,
    partial,
    parts: chunks.length,
    failedParts: failed.map((c) => ({ part: c.index + 1, lines: `${c.startLine}-${c.endLine}`, error: c.error })),
    totalLines: job.plan?.totalLines,
    modelCalls: chunks.reduce((s, c) => s + c.attempts, 0) + (report.summary_source === "model" ? 1 : 0),
    avgCallMs: metrics.length ? Math.round(metrics.reduce((s, m) => s + m.ms, 0) / metrics.length) : null,
    maxContextUsed: metrics.length ? Math.max(...metrics.map((m) => m.contextUsed)) : null,
    peakRssMb: metrics.length ? Math.max(...metrics.map((m) => m.rssMb)) : rssMb(),
    rejectedFindings: job.rejected.length,
    durationMs: Date.now() - Date.parse(job.startedAt),
    generatedAt: new Date().toISOString(),
  };
  job.report = report;
  if (!partial) job.status = failed.length ? "completed_with_errors" : "completed";
  log(job, `Report ready: ${report.findings.length} findings, ${report.incidents.length} incidents${failed.length ? `, ${failed.length} part(s) failed` : ""}`);
}

/** Reload persisted jobs at startup; unfinished ones are resumed. */
export function restoreJobs() {
  if (!fs.existsSync(JOBS_DIR)) return 0;
  let resumed = 0;
  for (const f of fs.readdirSync(JOBS_DIR).filter((f) => f.endsWith(".json"))) {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(JOBS_DIR, f), "utf8"));
      const { ledger, store, ...job } = data;
      job._ledger = new Ledger(ledger);
      job._store = new FindingStore(store);
      jobs.set(job.id, job);
      if (["queued", "planning", "running"].includes(job.status)) {
        log(job, "Server restarted; job will resume from the last checkpoint", "warn");
        queue.push(job.id);
        resumed++;
      }
    } catch (err) {
      console.error(`Skipping unreadable job file ${f}: ${err.message}`);
    }
  }

  return resumed;
}

/** Start processing queued (e.g. restored) jobs. Called once the model is loaded. */
export function startQueue() {
  kick();
}
