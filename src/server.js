import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import express from "express";
import { CONFIG, UPLOAD_DIR, ROOT_DIR, DEFAULT_MODEL_ID } from "./config.js";
import { llm } from "./llm.js";
import { createJob, getJob, listJobs, cancelJob, jobView, restoreJobs, startQueue, isBusy } from "./analyzer.js";

const app = express();
app.use(express.json({ limit: "16kb" }));
app.use(express.static(path.join(ROOT_DIR, "public")));
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

class HttpError extends Error {
  constructor(status, msg) {
    super(msg);
    this.status = status;
  }
}

/** Check that a saved upload looks like a text log (not binary, not empty). */
async function inspectUpload(file) {
  const fd = await fs.promises.open(file, "r");
  try {
    const { size } = await fd.stat();
    if (size === 0) throw new HttpError(400, "File is empty");
    const head = Buffer.alloc(Math.min(size, 64 * 1024));
    await fd.read(head, 0, head.length, 0);
    if (head.includes(0)) throw new HttpError(400, "File looks binary (contains NUL bytes); expected a text log");
    const text = new TextDecoder("utf-8", { fatal: false }).decode(head);
    const bad = (text.match(/�/g) || []).length;
    if (bad > text.length * 0.01) throw new HttpError(400, "File is not valid UTF-8 text");
    let lines = 0;
    let last = 10;
    for await (const buf of fs.createReadStream(file)) {
      for (const b of buf) if (b === 10) lines++;
      last = buf[buf.length - 1];
    }
    if (last !== 10) lines++; // final line without trailing newline
    return { size, lines, preview: text.split(/\r?\n/).slice(0, 3).map((l) => l.slice(0, 200)) };
  } finally {
    await fd.close();
  }
}

// Upload: raw request body streamed straight to disk (no in-memory copy).
app.post("/api/uploads", async (req, res, next) => {
  const name = path.basename(String(req.query.name || req.get("x-file-name") || ""));
  const ext = path.extname(name).toLowerCase();
  if (!name) return next(new HttpError(400, "Missing file name"));
  if (!CONFIG.allowedExtensions.includes(ext)) return next(new HttpError(400, `Only ${CONFIG.allowedExtensions.join(", ")} files are accepted`));
  const declared = Number(req.get("content-length") || 0);
  if (declared > CONFIG.maxUploadBytes) return next(new HttpError(413, `File too large (max ${CONFIG.maxUploadBytes / 1048576} MB)`));

  const id = crypto.randomUUID().slice(0, 8);
  const dest = path.join(UPLOAD_DIR, `${id}${ext}`);
  const out = fs.createWriteStream(dest);
  let received = 0;
  let aborted = false;
  req.on("data", (buf) => {
    received += buf.length;
    if (received > CONFIG.maxUploadBytes && !aborted) {
      aborted = true;
      req.unpipe(out);
      out.destroy();
      fs.rm(dest, { force: true }, () => {});
      next(new HttpError(413, `File too large (max ${CONFIG.maxUploadBytes / 1048576} MB)`));
    }
  });
  req.pipe(out);
  out.on("error", (err) => !aborted && next(err));
  out.on("finish", async () => {
    if (aborted) return;
    try {
      const info = await inspectUpload(dest);
      res.json({ uploadId: id, name, ...info });
    } catch (err) {
      fs.rm(dest, { force: true }, () => {});
      next(err);
    }
  });
});

app.post("/api/jobs", (req, res, next) => {
  const { uploadId, name, modelId = llm.modelInfo?.id || DEFAULT_MODEL_ID } = req.body || {};
  if (!/^[0-9a-f]{8}$/.test(String(uploadId))) return next(new HttpError(400, "Invalid uploadId"));
  const file = fs.readdirSync(UPLOAD_DIR).find((f) => f.startsWith(uploadId + "."));
  if (!file) return next(new HttpError(404, "Upload not found; upload the file again"));
  const model = llm.availableModels().find((m) => m.id === modelId);
  if (!model) return next(new HttpError(400, `Unknown model ${modelId}`));
  if (!model.downloaded) return next(new HttpError(400, `Model ${modelId} is not downloaded. Run: npm run download-model -- ${modelId}`));
  const filePath = path.join(UPLOAD_DIR, file);
  const job = createJob({ filePath, fileName: String(name || file).slice(0, 200), size: fs.statSync(filePath).size, modelId });
  res.status(202).json(jobView(job));
});

app.get("/api/jobs", (_req, res) => res.json(listJobs().map((j) => jobView(j))));

app.get("/api/jobs/:id", (req, res, next) => {
  const job = getJob(req.params.id);
  if (!job) return next(new HttpError(404, "Job not found"));
  res.json(jobView(job, { full: req.query.full === "1" }));
});

app.get("/api/jobs/:id/report", (req, res, next) => {
  const job = getJob(req.params.id);
  if (!job) return next(new HttpError(404, "Job not found"));
  if (!job.report) return next(new HttpError(409, `Report not ready (status: ${job.status})`));
  if (req.query.download === "1") res.attachment(`report-${job.id}.json`);
  res.json(job.report);
});

app.post("/api/jobs/:id/cancel", (req, res, next) => {
  if (!cancelJob(req.params.id)) return next(new HttpError(404, "Job not found"));
  res.json({ ok: true });
});

app.get("/api/models", (_req, res) => res.json(llm.availableModels()));

app.post("/api/models/select", async (req, res, next) => {
  try {
    if (isBusy()) throw new HttpError(409, "Cannot switch models while a job is running");
    const id = String(req.body?.id || "");
    const m = llm.availableModels().find((x) => x.id === id);
    if (!m) throw new HttpError(400, "Unknown model");
    if (!m.downloaded) throw new HttpError(400, `Model not downloaded. Run: npm run download-model -- ${id}`);
    await llm.load(id);
    res.json(llm.status());
  } catch (err) {
    next(err);
  }
});

app.get("/api/status", (_req, res) => {
  const mu = process.memoryUsage();
  res.json({
    model: llm.status(),
    memory: {
      rssMb: Math.round(mu.rss / 1048576),
      heapUsedMb: Math.round(mu.heapUsed / 1048576),
      limitMb: CONFIG.ramLimitMb,
      systemFreeMb: Math.round(os.freemem() / 1048576),
    },
    busy: isBusy(),
  });
});

app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: err.message || "Internal error" });
});

const server = app.listen(CONFIG.port, async () => {
  console.log(`Log analyzer on http://localhost:${CONFIG.port}`);
  // Restore job history first (visible immediately); resume only after the model is loaded.
  const resumed = restoreJobs();
  const def = llm.availableModels().find((m) => m.id === DEFAULT_MODEL_ID) || llm.availableModels().find((m) => m.downloaded);
  if (def?.downloaded) {
    try {
      await llm.load(def.id);
      console.log(`Model ${def.id} loaded in ${llm.loadMs} ms, RSS ${Math.round(process.memoryUsage().rss / 1048576)} MB`);
    } catch (err) {
      console.error(`Model load failed: ${err.message}`);
    }
  } else {
    console.warn("No model downloaded yet. Run: npm run download-model");
  }
  if (resumed) console.log(`Resuming ${resumed} unfinished job(s)`);
  startQueue();
});

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, async () => {
    server.close();
    await llm.unload().catch(() => {});
    process.exit(0);
  });
}
