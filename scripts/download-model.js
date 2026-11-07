// One-time setup: download GGUF model weights from Hugging Face into ./models.
// After this the app runs fully offline.
//   node scripts/download-model.js            -> default (qwen3.5-2b)
//   node scripts/download-model.js qwen3.5-0.8b
//   node scripts/download-model.js all
import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { MODELS, DEFAULT_MODEL_ID, MODELS_DIR } from "../src/config.js";

async function download(model) {
  const dest = path.join(MODELS_DIR, model.file);
  const part = dest + ".part";
  if (fs.existsSync(dest)) {
    console.log(`[skip] ${model.file} already present`);
    return;
  }
  fs.mkdirSync(MODELS_DIR, { recursive: true });
  const have = fs.existsSync(part) ? fs.statSync(part).size : 0;
  const headers = have ? { Range: `bytes=${have}-` } : {};
  console.log(`[get ] ${model.url}${have ? ` (resuming at ${have} bytes)` : ""}`);
  const res = await fetch(model.url, { headers, redirect: "follow" });
  if (!res.ok && res.status !== 206) throw new Error(`HTTP ${res.status} for ${model.url}`);
  const total = Number(res.headers.get("content-length") || 0) + (res.status === 206 ? have : 0);

  let done = res.status === 206 ? have : 0;
  let lastPrint = 0;
  const body = Readable.fromWeb(res.body);
  body.on("data", (buf) => {
    done += buf.length;
    const now = Date.now();
    if (now - lastPrint > 2000) {
      lastPrint = now;
      const pct = total ? ((done / total) * 100).toFixed(1) : "?";
      process.stdout.write(`  ${model.file}: ${(done / 1e6).toFixed(0)} MB / ${(total / 1e6).toFixed(0)} MB (${pct}%)\n`);
    }
  });
  await pipeline(body, fs.createWriteStream(part, { flags: res.status === 206 ? "a" : "w" }));
  if (total && fs.statSync(part).size !== total) throw new Error(`size mismatch for ${model.file}; re-run to resume`);
  fs.renameSync(part, dest);
  console.log(`[done] ${dest}`);
}

const arg = process.argv[2] || DEFAULT_MODEL_ID;
const targets = arg === "all" ? MODELS : MODELS.filter((m) => m.id === arg);
if (!targets.length) {
  console.error(`Unknown model "${arg}". Options: ${MODELS.map((m) => m.id).join(", ")}, all`);
  process.exit(1);
}
for (const m of targets) {
  try {
    await download(m);
  } catch (err) {
    console.error(`[fail] ${m.id}: ${err.message}`);
    process.exitCode = 1;
  }
}
