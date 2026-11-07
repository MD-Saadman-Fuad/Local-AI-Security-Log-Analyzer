// Token-aware, line-preserving splitter.
//
// The file is streamed once to build a *plan*: a list of chunks described only
// by line range + byte range + token count. No chunk text is kept in memory.
// When a chunk is processed its byte range is read back from disk, so at any
// moment only one chunk of log text is resident (no extra copies of the log).
import fs from "node:fs";
import { normalizeLine, isContinuation } from "./normalize.js";

/**
 * Stream a file and yield { lineNo, raw, startByte, endByte } per line.
 * Handles \n and \r\n, and a final line without newline.
 */
export async function* readLines(filePath, { start = 0, end = Infinity, firstLineNo = 1 } = {}) {
  const stream = fs.createReadStream(filePath, {
    start,
    end: end === Infinity ? undefined : end - 1,
    highWaterMark: 64 * 1024,
  });
  let pending = Buffer.alloc(0);
  let offset = start;
  let lineNo = firstLineNo;
  for await (const buf of stream) {
    let data = pending.length ? Buffer.concat([pending, buf]) : buf;
    let idx;
    let from = 0;
    while ((idx = data.indexOf(0x0a, from)) !== -1) {
      const lineBuf = data.subarray(from, idx);
      const raw = lineBuf.toString("utf8").replace(/\r$/, "");
      yield { lineNo: lineNo++, raw, startByte: offset, endByte: offset + (idx - from) + 1 };
      offset += idx - from + 1;
      from = idx + 1;
    }
    pending = Buffer.from(data.subarray(from));
  }
  if (pending.length) {
    yield { lineNo, raw: pending.toString("utf8").replace(/\r$/, ""), startByte: offset, endByte: offset + pending.length };
  }
}

/** The exact text the model sees for one line. */
export const formatLine = (lineNo, text) => `L${lineNo} ${text}`;

/**
 * Build the chunk plan.
 * @param {string} filePath
 * @param {(text:string)=>number} countTokens  tokenizer of the loaded model
 * @param {number} logBudget  max tokens of log text per chunk
 */
export async function planChunks(filePath, countTokens, logBudget) {
  const chunks = [];
  let cur = null; // chunk being filled
  let entry = null; // current multi-line entry (kept together if possible)
  let totalLines = 0;
  let totalTokens = 0;
  let rawTokensSample = 0;

  const newChunk = (e) => ({
    index: chunks.length,
    startLine: e.startLine,
    endLine: e.endLine,
    startByte: e.startByte,
    endByte: e.endByte,
    tokens: 0,
    cutEntry: false,
  });

  const flushEntry = () => {
    if (!entry) return;
    if (cur && cur.tokens + entry.tokens > logBudget) {
      chunks.push(cur);
      cur = null;
    }
    if (!cur) cur = newChunk(entry);
    cur.endLine = entry.endLine;
    cur.endByte = entry.endByte;
    cur.tokens += entry.tokens;
    entry = null;
  };

  for await (const ln of readLines(filePath)) {
    totalLines++;
    if (!ln.raw.trim()) continue; // blank lines carry no information
    const { text } = normalizeLine(ln.raw);
    const tokens = countTokens(formatLine(ln.lineNo, text)) + 1; // +1 for newline
    totalTokens += tokens;
    if (totalLines <= 200) rawTokensSample += countTokens(ln.raw);

    if (entry && isContinuation(ln.raw) && entry.tokens + tokens <= logBudget) {
      entry.endLine = ln.lineNo;
      entry.endByte = ln.endByte;
      entry.tokens += tokens;
      continue;
    }
    if (entry && isContinuation(ln.raw)) {
      // Entry alone is bigger than a whole chunk: it has to be cut. Mark it.
      flushEntry();
      chunks.push(cur);
      cur = null;
      entry = { startLine: ln.lineNo, endLine: ln.lineNo, startByte: ln.startByte, endByte: ln.endByte, tokens };
      flushEntry();
      cur.cutEntry = true;
      continue;
    }
    flushEntry();
    entry = { startLine: ln.lineNo, endLine: ln.lineNo, startByte: ln.startByte, endByte: ln.endByte, tokens: Math.min(tokens, logBudget) };
  }
  flushEntry();
  if (cur) chunks.push(cur);

  return { chunks, totalLines, compactTokens: totalTokens, rawTokensSample };
}

/** Read one chunk's lines back from disk (only this chunk is materialized). */
export async function loadChunkLines(filePath, chunk, countTokens, lineBudget) {
  const lines = [];
  for await (const ln of readLines(filePath, { start: chunk.startByte, end: chunk.endByte, firstLineNo: chunk.startLine })) {
    if (!ln.raw.trim()) continue;
    const norm = normalizeLine(ln.raw);
    let text = norm.text;
    // A single line larger than the whole budget is truncated (and labelled).
    if (countTokens && lineBudget && countTokens(text) > lineBudget) {
      text = text.slice(0, Math.max(50, Math.floor(lineBudget * 2.5))) + " …[line truncated]";
    }
    lines.push({ lineNo: ln.lineNo, text, facts: norm.facts });
  }
  return lines;
}
