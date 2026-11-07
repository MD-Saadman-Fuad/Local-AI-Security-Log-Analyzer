// Dashboard. All log-derived text is inserted with esc() — log content is untrusted.
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
let upload = null;
let currentJob = null;
let pollTimer = null;

async function api(url, opts = {}) {
  const res = await fetch(url, opts);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

// ---- system status (RAM, model timing) ----
async function refreshStatus() {
  try {
    const s = await api("/api/status");
    const m = s.model;
    $("sys").innerHTML = [
      m.model ? `model: ${esc(m.model.label)} (loaded in ${(m.loadMs / 1000).toFixed(1)}s, ${m.threads} threads, ctx ${m.contextSize})` : "model: not loaded",
      `RAM: ${s.memory.rssMb} MB / ${s.memory.limitMb} MB limit`,
      m.calls ? `calls: ${m.calls} · avg ${(m.avgCallMs / 1000).toFixed(1)}s · ${m.timeouts} timeouts · max ctx ${m.maxContextUsed}` : "",
    ].filter(Boolean).join("<br>");
  } catch {
    $("sys").textContent = "Server unreachable";
  }
}

async function loadModels() {
  const models = await api("/api/models");
  $("model").innerHTML = models
    .map((m) => `<option value="${esc(m.id)}" ${m.active ? "selected" : ""} ${m.downloaded ? "" : "disabled"}>${esc(m.label)}${m.downloaded ? ` · ${m.sizeMb} MB` : " (not downloaded)"}</option>`)
    .join("");
}

// ---- upload ----
async function handleFile(file) {
  $("setupErr").textContent = "";
  $("start").disabled = true;
  upload = null;
  if (!file) return;
  if (!/\.(log|txt)$/i.test(file.name)) {
    $("setupErr").textContent = "Please choose a .log or .txt file.";
    return;
  }
  $("dropText").textContent = `Uploading ${file.name}…`;
  try {
    upload = await api(`/api/uploads?name=${encodeURIComponent(file.name)}`, { method: "POST", body: file, headers: { "Content-Type": "application/octet-stream" } });
    $("dropText").innerHTML = `<b>${esc(upload.name)}</b> ready`;
    $("uploadInfo").textContent = `${(upload.size / 1024).toFixed(1)} KB · ${upload.lines} lines`;
    $("start").disabled = false;
  } catch (err) {
    $("dropText").textContent = "Drop a .log or .txt file here, or click to choose";
    $("setupErr").textContent = `Upload rejected: ${err.message}`;
  }
}
$("file").addEventListener("change", (e) => handleFile(e.target.files[0]));
const drop = $("drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); handleFile(e.dataTransfer.files[0]); });

$("start").addEventListener("click", async () => {
  if (!upload) return;
  $("start").disabled = true;
  try {
    const job = await api("/api/jobs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ uploadId: upload.uploadId, name: upload.name, modelId: $("model").value }) });
    watch(job.id);
  } catch (err) {
    $("setupErr").textContent = err.message;
    $("start").disabled = false;
  }
});

$("cancel").addEventListener("click", () => currentJob && api(`/api/jobs/${currentJob}/cancel`, { method: "POST" }));

// ---- progress ----
function watch(id) {
  currentJob = id;
  $("progressCard").classList.remove("hidden");
  $("reportCard").classList.add("hidden");
  clearInterval(pollTimer);
  poll();
  pollTimer = setInterval(poll, 1500);
}

const FINAL = ["completed", "completed_with_errors", "failed", "cancelled"];
async function poll() {
  try {
    const j = await api(`/api/jobs/${currentJob}?full=1`);
    $("jobStatus").textContent = j.status.replace(/_/g, " ");
    $("barFill").style.width = `${j.progress.pct}%`;
    $("progressText").textContent = `${j.progress.partsDone} / ${j.progress.partsTotal || "?"} parts analysed · ${j.findingsSoFar} merged findings so far` + (j.error ? ` · error: ${j.error}` : "");
    $("parts").innerHTML = (j.plan?.chunks || [])
      .map((c) => `<div class="part ${c.status}" title="Part ${c.index + 1}: lines ${c.startLine}-${c.endLine}, ${c.tokens} tokens${c.metrics ? `, ${(c.metrics.ms / 1000).toFixed(1)}s, ctx ${c.metrics.contextUsed}` : ""}${c.error ? `, ${esc(c.error)}` : ""}"></div>`)
      .join("");
    const ev = $("events");
    ev.textContent = j.events.map((e) => `${e.t.slice(11, 19)} ${e.level === "info" ? "" : e.level.toUpperCase() + " "}${e.msg}`).join("\n");
    ev.scrollTop = ev.scrollHeight;
    $("cancel").classList.toggle("hidden", FINAL.includes(j.status));
    if (FINAL.includes(j.status)) {
      clearInterval(pollTimer);
      $("start").disabled = !upload;
      loadJobs();
      if (j.status !== "failed") showReport(currentJob);
    }
  } catch (err) {
    $("progressText").textContent = `Lost contact with server (${err.message}); retrying…`;
  }
  refreshStatus();
}

// ---- report ----
async function showReport(id) {
  const r = await api(`/api/jobs/${id}/report`);
  $("reportCard").classList.remove("hidden");
  $("download").href = `/api/jobs/${id}/report?download=1`;
  $("counts").innerHTML = ["Critical", "High", "Medium", "Low"].map((s) => `<div class="count"><b>${r.counts[s]}</b><span class="sev ${s}">${s}</span></div>`).join("");
  $("summary").innerHTML = `${esc(r.summary)} <span class="tag">${r.summary_source === "model" ? "written by local model" : "template"}</span>`;
  $("priorities").innerHTML = (r.top_priorities || []).map((p) => `<li>${esc(p)}</li>`).join("");
  const m = r.meta;
  $("meta").innerHTML = `${esc(m.file)} · model ${esc(m.model)} · ${m.totalLines} lines in ${m.parts} parts · ${m.modelCalls} model calls · avg ${(m.avgCallMs / 1000).toFixed(1)}s/call · max context ${m.maxContextUsed}/2048 tokens · peak RAM ${m.peakRssMb} MB · ${(m.durationMs / 60000).toFixed(1)} min · ${m.rejectedFindings} unsupported findings rejected` +
    (m.partial ? " · <b>partial report (cancelled)</b>" : "") +
    (m.failedParts.length ? `<br><b>Not analysed by the model:</b> ${m.failedParts.map((f) => `part ${f.part} (lines ${f.lines})`).join(", ")}` : "");

  $("incidents").innerHTML = r.incidents.length
    ? r.incidents.map((i) => `<div class="incident">
        <span class="sev ${i.severity}">${i.severity}</span> <b>${esc(i.entity)}</b>
        ${i.users.length ? `<span class="muted small">user ${esc(i.users.join(", "))}</span>` : ""}
        ${i.spans_multiple_parts ? `<span class="tag">linked across parts ${i.parts.join(", ")}</span>` : `<span class="tag">part ${i.parts.join(", ")}</span>`}
        <div class="chain">${i.steps.map((s) => `<span class="step"><span class="sev ${s.severity}">${s.severity[0]}</span> ${esc(s.attack_type)} <span class="muted">L${s.first_line}${s.last_line !== s.first_line ? "–" + s.last_line : ""}</span></span>`).join("<span>→</span>")}</div>
      </div>`).join("")
    : `<p class="muted">No incidents.</p>`;

  $("findings").innerHTML = r.findings.length
    ? r.findings.map((f) => `<details class="finding">
        <summary><span class="sev ${f.severity}">${f.severity}</span><b>${esc(f.attack_type)}</b> <span>${esc(f.entity)}</span>
          <span class="muted small">L${f.first_line}${f.last_line !== f.first_line ? "–L" + f.last_line : ""} · ${f.evidence_lines.length} lines · parts ${f.parts.join(", ")}</span>
          ${f.sources.map((s) => `<span class="tag">${esc(s)}</span>`).join("")}<span class="tag">confidence ${esc(f.confidence)}</span></summary>
        <div class="body">
          <p><b>Why:</b> ${esc(f.reason)}</p>
          ${f.other_reasons.length ? `<p class="muted small">Also noted: ${f.other_reasons.map(esc).join(" · ")}</p>` : ""}
          <p><b>Suggested action:</b> ${esc(f.action)}</p>
          ${f.notes.length ? `<p class="muted small">Notes: ${f.notes.map(esc).join("; ")}</p>` : ""}
          <div class="ev">${f.evidence.map((e) => `L${e.line}  ${esc(e.text)}`).join("\n")}${f.more_evidence ? `\n… ${f.more_evidence} more lines: ${f.evidence_lines.slice(12).map((n) => "L" + n).join(", ")}` : ""}</div>
        </div></details>`).join("")
    : `<p class="muted">No suspicious activity found.</p>`;
}

async function loadJobs() {
  const jobs = await api("/api/jobs");
  $("jobs").innerHTML = jobs.length
    ? jobs.map((j) => `<div class="jobrow" data-id="${esc(j.id)}"><b>${esc(j.fileName)}</b><span>${esc(j.status)}</span><span class="muted">${esc(j.modelId)} · ${new Date(j.createdAt).toLocaleString()}</span></div>`).join("")
    : "None yet";
  document.querySelectorAll(".jobrow").forEach((el) => el.addEventListener("click", () => watch(el.dataset.id)));
  const running = jobs.find((j) => !FINAL.includes(j.status));
  if (running && !currentJob) watch(running.id); // reconnect after page reload
}

$("model").addEventListener("change", async (e) => {
  $("setupErr").textContent = `Loading ${e.target.value}…`;
  try {
    await api("/api/models/select", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: e.target.value }) });
    $("setupErr").textContent = "";
  } catch (err) {
    $("setupErr").textContent = err.message;
  }
  loadModels();
  refreshStatus();
});

loadModels();
loadJobs();
refreshStatus();
setInterval(refreshStatus, 5000);
