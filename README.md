# Local AI Security Log Analyzer

A web app that finds possible attacks in server logs using a **local** language model
(Qwen3.5 2B, CPU-only, llama.cpp). Log files bigger than the model's 2,048-token window
are split into parts, each part is analysed by the model, facts are carried between calls,
and everything is merged and correlated into one final report.

```
upload ──► plan (token-aware split) ──► for each part:                     ──► correlate ──► summary ──► report
                                          memory (ledger) + part ─► model        across all     (1 more
                                          validate ─► merge ─► checkpoint        parts          model call)
```

**Documents:** [User manual](USER_MANUAL.md) · [AI usage & prompts](AI_USAGE.md) ·
[Presentation script](SCRIPT.md) · Demo video: _add link here_

## Setup

Requirements: Node.js ≥ 20, ~2 GB disk. No GPU, Python or Docker needed.

```bash
git clone <this-repo-url> && cd <repo-folder>
npm install                      # also fetches the prebuilt llama.cpp binaries (node-llama-cpp)
npm run download-model           # Qwen3.5-2B-Q4_K_M.gguf (1.28 GB) into ./models
npm run download-model -- qwen3.5-0.8b   # optional faster/smaller model (533 MB)
npm start                        # http://localhost:3000
npm test                         # unit tests (no model needed)
npm run smoke                    # optional: load the model and analyse one part of the sample
```

Model weights, uploads and job data are not in the repository (`models/`, `data/` are git-ignored);
they are created locally by the commands above.

After these steps the app runs **fully offline** — no cloud AI or network calls at runtime.

Open http://localhost:3000, drop a `.log`/`.txt` file, press **Start analysis**, watch progress
per part, then read the report (or download it as JSON). A sample is in `samples/`.

Environment overrides (see `src/config.js`): `PORT`, `MODEL_ID`, `LLM_THREADS` (default 2),
`CALL_TIMEOUT_MS` (180000), `MAX_RETRIES` (2), `MAX_OUTPUT_TOKENS` (400), `MAX_MEMORY_TOKENS` (260),
`MAX_UPLOAD_MB` (25).

## Model details

| | Default | Alternative |
|---|---|---|
| Model | Qwen3.5 2B Instruct, Q4_K_M GGUF (unsloth) | Qwen3.5 0.8B, Q4_K_M |
| File size | 1.28 GB | 0.53 GB |
| Runtime | llama.cpp via `node-llama-cpp` 3.22, in-process, CPU, **2 threads** | same |
| Context | 2,048 tokens, 1 sequence | same |
| Load time | ~4.5 s | ~3.5 s |
| Speed (measured, 2 threads) | avg 33.5 s per part (1,401 prompt + 108 output tokens) | ~11 s per part |
| Peak process RSS | 2,046 MB (model mmap + KV cache + Node; Node heap ~40 MB) | ~1.0 GB |

* Text only: the vision projector (`mmproj`) is never downloaded or loaded.
* **Thinking is disabled** in the chat template (`QwenChatWrapper({thoughts:"discourage"})`):
  hidden reasoning would consume the 2k budget (it produced empty answers in testing).
* **Grammar-constrained JSON**: a GBNF grammar generated from a JSON schema (`src/prompts.js`)
  is applied at decode time, so the model can only emit valid JSON with the expected keys,
  enum values for attack type/severity, and bounded array/string lengths. The grammar is generated
  in compact form (no newlines/indentation) which cut output tokens ~40%.
* Switch model from the dropdown in the UI (`POST /api/models/select`), or `MODEL_ID=qwen3.5-0.8b`.
  The 0.8B model is 3× faster but missed obvious attacks in testing, so 2B is the default.

## Token budget (per call, 2,048 total)

Measured with the model's own tokenizer *and* chat template (`llm.promptTokens()`), not estimated:

| Slice | Tokens | Notes |
|---|---|---|
| System prompt + template + user scaffolding | 647 | measured once per job |
| Carried context ("Known context") | ≤ 260 | rendered to fit; shrunk further if needed |
| Log text | ≤ 693 | `2048 − 647 − 260 − 400 − 48`, used by the splitter |
| Reserved for the JSON reply | 400 | `maxTokens` of the call; typical reply 90–260 |
| Safety margin | 48 | |

Before every call the exact prompt size is recomputed; if `prompt + 400 > 2048` the memory block
is shrunk until it fits, and the call is refused rather than silently truncated. The UI and report
show the real context used per call (max observed 1,814 / 2,048).

## Result on the sample log (`samples/`, 258 lines)

Final run: 18 parts, 19 model calls, 11.8 min, peak RSS 2,050 MB, max context 1,889 / 2,048, 0 failed parts,
0 false positives (an earlier run also had 1 timeout, retried successfully):

| Severity | Type | Entity | Evidence | Source |
|---|---|---|---|---|
| Critical | Account Compromise | 203.0.113.44 | 12 failed logins L5…L189 → success L196 → `/admin/users` L198 → export L201 (parts 1–14) | correlation |
| Critical | Data Exfiltration | 203.0.113.44 | 2.8 MB CSV export L201 after the compromise | model + correlation |
| High | Brute Force | 203.0.113.44 | L5, L13, … L189 across 11 parts | model + correlation |
| High | Malicious Input | 203.0.113.201 | L217 "Ignore previous instructions…" (reported, not obeyed) | model |
| Medium | SQL Injection | 203.0.113.72 | L29, L30 (start) and L222, L223 (end) | model |
| Medium | Scanning | 203.0.113.90 | `.env`, `.git/config`, `wp-admin`, `actuator` L54–L62 | model |
| Medium | Path Traversal | 203.0.113.90 | `../../etc/passwd`, double-encoded, L99, L101 | model |
| High | High Request Rate | 203.0.113.155 | 124–135 req/10 s, 429s, L159–L170 | model |
| Medium | Unauthorized Access | 203.0.113.90 | `/api/v1/admin/settings` 403 (L102) after traversal attempts | model |
| Medium | Unauthorized Access | 203.0.113.44 | admin endpoint right after the compromised login (L196, L198) | model |

Correctly *not* reported (10 model claims rejected with reasons): deploy 503s, DB timeouts, a single 422,
a user's single typo then success (L238–239), and ordinary 200/304 browser traffic.
Severities vary a little between runs (small model); the Critical chain comes from correlation and is stable.

## Log splitting method (`src/normalize.js`, `src/chunker.js`)

1. **Stream, don't load.** The file is read once as a byte stream. The plan stores only
   `startLine/endLine/startByte/endByte/tokens` per part — no log text is kept in memory.
   When a part is processed its byte range is read back from disk, so only one part's text
   is resident at a time (no extra copies of the log).
2. **Normalize each line** to a compact form the model can read cheaply, keeping the original
   line number: `L29 08:18:50 203.0.113.72 GET /api/v1/crops?search=' OR 1=1-- 400 rule=invalid_query_parameter ua=curl/8.7.1`.
   JSON logs, Apache/Nginx combined format and syslog/SSH lines are recognised; anything else
   is passed through as trimmed text. Noise (request ids, hostnames, browser UA strings) is dropped;
   URL-encoding is decoded (double encoding is flagged, e.g. `%252e%252e` → `../ [double-encoded]`);
   large responses (`bytes=`), slow calls, auth results, rate counters are kept.
   For the sample file this reduces ~39k raw tokens to **11.6k**, i.e. 18 parts instead of ~60.
3. **Token-aware packing.** Lines are counted with the model's tokenizer and packed greedily
   into parts of ≤ 892 tokens. **Entries are never cut**: continuation lines (stack traces,
   indented lines, `Caused by`, `Traceback`) stay with their first line. Only an entry larger than
   a whole part is cut, and the part is marked `cutEntry`. A single gigantic line is truncated with
   a visible `…[line truncated]` marker.
4. No overlap between parts — linking across parts is done by the ledger (below), which is
   cheaper than re-sending lines.

## Linking events across parts

**Ledger (`src/ledger.js`)** — after each part, per-IP facts are accumulated from the *parsed*
fields: failed/successful logins (with line numbers), usernames, 401/403/404 counts, sensitive
paths (admin/export/.env/…), large downloads, peak requests per 10 s, and the attack types the
model has already reported for that IP. Before the next call the most relevant entries
(IPs present in the next part first, then highest risk) are rendered into the prompt within the
memory budget, e.g.:

```
- 203.0.113.44: user=workspace.admin; 11 failed logins (L5,L13…L189); already reported: Brute Force/High
```

So when the model sees `L196 … 203.0.113.44 POST /api/v1/auth/login 200 auth=success` near the end of
the file it knows about the failures from the start and middle.

**Correlation (`src/aggregate.js → correlate`)** — after the last part, the whole-file ledger is
used to link events deterministically: an IP with ≥3 failed logins spread across parts becomes one
Brute Force finding with all lines; a later success from the same IP becomes **Account Compromise
(Critical)** with the failures, the success and any following sensitive actions (admin pages,
large export) as evidence. These findings are tagged `correlation`; model findings are tagged `model`.

**Merging** — findings are keyed by `(attack type, entity)`; repeats from different parts are merged
(evidence lines unioned, highest severity kept, reasons kept). **Incidents** group all findings of
one entity in file order (e.g. `Brute Force → Account Compromise → Data Exfiltration`) and show
which parts they span.

## Accuracy safeguards

* Every finding is **validated against the real lines** of the part: line numbers outside the part
  are dropped, the entity must appear in the evidence lines (otherwise it's replaced by the dominant
  IP in those lines), and findings with no remaining evidence are rejected (counted in the report).
* **Every finding needs at least one evidence line with a security signal**: 401/403/429, an auth
  event, an attack payload or probe path in the URL, a rate counter, a ≥1 MB response, a WAF rule, or
  free text submitted by a client. A plain error status (422, 500, 503) or a 200/304 is *not* a signal,
  so ordinary application errors and normal traffic cannot become attack findings.
* Claims contradicted by the parsed facts are rejected: Brute Force / Account Compromise need ≥3 failed
  logins from that IP (one typo followed by success is a normal user); High Request Rate needs a peak
  ≥ 20 requests in 10 s.
* Rejected claims are not hidden: they are listed with their reason in the job (`?full=1` → `rejected`)
  and counted in the report.
* The prompt explicitly lists normal errors (DB timeouts, 5xx during deploy, health checks).

## Prompt-injection handling

Log text is data: it is placed inside `<log>…</log>`, free-text fields are JSON-quoted and clipped,
and the system prompt says to report instructions in logs as **Malicious Input** instead of following
them. Structurally, the model can only output the JSON schema (no tools, no commands are ever executed),
and **the carried memory is built only from parsed fields and enum values, never from model or log
free text**, so an injected sentence cannot propagate into later prompts. Even the parsed fields are
attacker-controlled, so only IP-shaped values (`[0-9a-f:.]`) become memory keys and usernames are
reduced to `[\w.@-]`, max 32 chars (unit-tested). Correlation findings come
from code, so a manipulated model reply cannot "remove failed login evidence". All log-derived text is
HTML-escaped in the UI.

## Reliability

* **Uploads**: only `.log`/`.txt`, streamed to disk (no buffering), size limit (25 MB), rejected if
  empty, binary (NUL bytes) or not UTF-8.
* **One call at a time** (mutex around the single 2k context) and **one job at a time** (queue).
* **Timeouts**: each call is aborted after 180 s (`AbortSignal`), the context is cleared.
* **Retries**: up to 2 retries per part with slightly higher temperature; if still failing the part is
  **split in half** and each half retried (smaller prompt/output). If that fails too, the part is marked
  failed, its facts are still recorded in the ledger (so correlation still sees those lines), and the job
  continues → status `completed_with_errors`; the report lists the unanalysed line ranges.
* **Broken JSON**: grammar makes it rare; `src/jsonRepair.js` still handles fences, `<think>` blocks,
  trailing commas, truncated output (closes open brackets) and salvages complete objects.
* **Checkpoints / resume**: job state (plan, per-part status, ledger, merged findings) is written
  atomically to `data/jobs/<id>.json` after every part. On restart, unfinished jobs resume from the
  next pending part. Cancel keeps findings so far and produces a partial report.
* **Offline + resource limits enforced in code**: llama.cpp is started with `build:"never"`,
  `skipDownload:true` (it can never fetch or compile anything at runtime) and `maxThreads: 2`; a model
  is refused if `weights + 0.9 GB` exceeds the 4 GB limit; Node heap capped at 512 MB.
* **Duplicate log lines** (same `request_id` logged twice) are counted once in the ledger.
* **Resource display**: header shows process RSS vs. the 4 GB limit, model load time, average call time,
  timeouts and max context used; per-part timings are in the progress tooltips and report meta.

## API

| Method | Path | |
|---|---|---|
| POST | `/api/uploads?name=file.log` | raw body upload → `{uploadId, lines, size}` |
| POST | `/api/jobs` | `{uploadId, modelId?}` → starts analysis |
| GET | `/api/jobs/:id[?full=1]` | status, progress, events (plan + metrics with `full=1`) |
| GET | `/api/jobs/:id/report[?download=1]` | final report JSON |
| POST | `/api/jobs/:id/cancel` | cancel, keep partial findings |
| GET/POST | `/api/models`, `/api/models/select` | list / switch local model |
| GET | `/api/status` | model, RAM, timing |

## Project layout

```
src/config.js      limits and token budget
src/normalize.js   line parsing + compaction + facts
src/chunker.js     streaming, token-aware, entry-preserving splitter
src/ledger.js      cross-part memory
src/prompts.js     prompts + JSON schemas
src/llm.js         llama.cpp runtime, tokenizer, grammar, timeout
src/jsonRepair.js  tolerant JSON parsing
src/aggregate.js   validation, merge, correlation, report
src/analyzer.js    job queue, retries, checkpoints, summary call
src/server.js      HTTP API + upload validation
public/            dashboard (plain HTML/JS)
test/              unit tests (node:test)
scripts/           model download + smoke test
samples/           sample log used in the results above
models/            downloaded GGUF weights (git-ignored)
data/              uploads + job checkpoints (git-ignored, created at runtime)
```

## Known limits

* Speed: ~34 s per part on 2 CPU threads with the 2B model → ~14 minutes for the sample. A call can occasionally
  stall (one 180 s timeout seen in testing; the retry succeeded).
* Correlation is per IP; attacks distributed over many IPs (credential stuffing against one user) are
  only visible to the model within a part, not linked across parts.
* Request-rate detection relies on what the model sees within one part plus the ledger's 10-second
  peak; very slow, long-running floods are not specially modelled.
* Small models are inconsistent about severity; correlation rules and validation reduce but don't
  remove this. The 0.8B model misses many attacks.
* Timestamps in the compact form are shown as time-of-day only; multi-day logs lose the date in the
  model's view (ordering still comes from line numbers).
* RSS on Windows counts memory-mapped model pages; the number shown is the whole process.
* No authentication on the dashboard — intended for local use.
