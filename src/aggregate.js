// Validation, merging and cross-part correlation of model findings.
import { ATTACK_TYPES, SEVERITIES } from "./prompts.js";
import { readLines } from "./chunker.js";
import { normalizeLine } from "./normalize.js";

const SEV_RANK = { Low: 1, Medium: 2, High: 3, Critical: 4 };
const CONF_RANK = { low: 1, medium: 2, high: 3 };
const maxSev = (a, b) => (SEV_RANK[a] >= SEV_RANK[b] ? a : b);

export const DEFAULT_ACTIONS = {
  "Brute Force": "Block or rate-limit the source IP, enforce MFA and account lockout",
  "Account Compromise": "Revoke active sessions, reset the account password, review actions taken after login",
  "SQL Injection": "Block the source at the WAF and verify parameterized queries on the endpoint",
  "Path Traversal": "Block the source and verify file-path input is canonicalized and whitelisted",
  Scanning: "Block the scanner IP and ensure sensitive files are not served",
  "Unauthorized Access": "Review access controls on the targeted resources and block the source",
  "High Request Rate": "Apply per-IP rate limiting and monitor for service impact",
  "Data Exfiltration": "Investigate the exported data, revoke the session and notify data owners",
  "Malicious Input": "Keep input validation in place; review the submitted content and block the source if repeated",
  "Other Suspicious": "Review the evidence manually",
};

function canonType(t) {
  if (!t) return "Other Suspicious";
  if (ATTACK_TYPES.includes(t)) return t;
  const s = String(t).toLowerCase();
  const map = [
    [/brute|password guess|failed login|credential/, "Brute Force"],
    [/compromis|takeover|successful login/, "Account Compromise"],
    [/sql|sqli|union/, "SQL Injection"],
    [/travers|lfi|\.\.\//, "Path Traversal"],
    [/scan|recon|probe|enumerat/, "Scanning"],
    [/unauthori|forbidden|privilege|access/, "Unauthorized Access"],
    [/rate|dos|flood|throttl/, "High Request Rate"],
    [/exfil|export|download|leak/, "Data Exfiltration"],
    [/inject|malicious|prompt/, "Malicious Input"],
  ];
  for (const [re, name] of map) if (re.test(s)) return name;
  return "Other Suspicious";
}

const canonSev = (s) => SEVERITIES.find((x) => x.toLowerCase() === String(s || "").toLowerCase()) || "Medium";
const canonConf = (c) => (["low", "medium", "high"].includes(String(c).toLowerCase()) ? String(c).toLowerCase() : "medium");

function lineMentions(line, entity) {
  const f = line.facts;
  return f.ip === entity || f.user === entity || f.session === entity || line.text.includes(entity);
}

/**
 * Validate the raw findings of one chunk against that chunk's real lines.
 * Returns { accepted: [...], rejected: [{finding, why}] }.
 */
export function validateFindings(rawFindings, chunkLines, ledger) {
  const byLine = new Map(chunkLines.map((l) => [l.lineNo, l]));
  const accepted = [];
  const rejected = [];
  for (const raw of Array.isArray(rawFindings) ? rawFindings : []) {
    if (!raw || typeof raw !== "object") continue;
    const nums = (Array.isArray(raw.lines) ? raw.lines : [raw.lines])
      .map((n) => Number(String(n).replace(/^L/i, "")))
      .filter((n) => Number.isInteger(n) && byLine.has(n));
    if (!nums.length) {
      rejected.push({ finding: raw, why: "no evidence line inside this part" });
      continue;
    }
    let entity = String(raw.entity || "").trim();
    let evidence = nums.map((n) => byLine.get(n));
    if (entity && !evidence.some((l) => lineMentions(l, entity))) {
      // Right entity, wrong line numbers: re-anchor to this part's lines of that entity.
      const own = chunkLines.filter((l) => lineMentions(l, entity)).slice(0, 8);
      if (own.length) evidence = own;
    }
    if (!entity || !evidence.some((l) => lineMentions(l, entity))) {
      // Model named an entity the evidence does not contain: use the dominant IP instead.
      const counts = {};
      for (const l of evidence) if (l.facts.ip) counts[l.facts.ip] = (counts[l.facts.ip] || 0) + 1;
      entity = Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || evidence[0].facts.user || "unknown";
    }
    if (entity !== "unknown") evidence = evidence.filter((l) => lineMentions(l, entity));
    if (!evidence.length) {
      rejected.push({ finding: raw, why: "evidence lines do not mention the entity" });
      continue;
    }

    const f = {
      attack_type: canonType(raw.attack_type),
      severity: canonSev(raw.severity),
      confidence: canonConf(raw.confidence),
      entity,
      lines: evidence.map((l) => l.lineNo),
      evidence: evidence.map((l) => ({ line: l.lineNo, text: l.text })),
      reason: String(raw.reason || "").slice(0, 300),
      action: String(raw.action || "").slice(0, 200),
      notes: [],
    };

    // Guardrails against calling normal errors attacks.
    const hasClient = evidence.some((l) => l.facts.ip || l.facts.user);
    if (!hasClient) {
      f.severity = "Low";
      f.confidence = "low";
      f.notes.push("evidence contains no client identity; likely an application error, review manually");
    }
    // "Unauthorized Access" whose evidence is only failed logins is the brute-force finding.
    if (f.attack_type === "Unauthorized Access" && evidence.every((l) => l.facts.auth === "fail")) f.attack_type = "Brute Force";

    // Claims contradicted by the parsed facts are rejected (kept in the job's
    // "rejected" list for transparency) instead of being reported as attacks.
    const led = ledger.ips[entity];
    const fails = led?.authFail.length ?? 0;
    const why = evidence.every((l) => l.facts.signal === false)
      ? "evidence is normal traffic or ordinary errors (no payload, auth event, 401/403/429, rate or large download)"
      : (f.attack_type === "Brute Force" || f.attack_type === "Account Compromise") && led && fails < 3
        ? `only ${fails} failed login(s) for this IP so far; normal user behaviour`
        : f.attack_type === "High Request Rate" && led && led.peakRate < 20
          ? `request rate not supported by the log (peak ${led.peakRate} requests/10s)`
          : null;
    if (why) {
      rejected.push({ finding: raw, why });
      continue;
    }
    accepted.push(f);
  }
  return { accepted, rejected };
}

/** Merges findings across parts: one entry per (attack type, entity). */
export class FindingStore {
  constructor(data) {
    this.items = data?.items || {};
  }
  toJSON() {
    return { items: this.items };
  }
  add(f, chunkIndex, source = "model") {
    const key = `${f.attack_type}|${f.entity}`;
    const m = (this.items[key] ||= {
      attack_type: f.attack_type,
      entity: f.entity,
      severity: f.severity,
      confidence: f.confidence,
      lines: [],
      evidence: {},
      reasons: [],
      actions: [],
      notes: [],
      chunks: [],
      sources: [],
      mentions: 0,
    });
    m.mentions++;
    m.severity = maxSev(m.severity, f.severity);
    if (CONF_RANK[f.confidence] > CONF_RANK[m.confidence]) m.confidence = f.confidence;
    for (const e of f.evidence || []) {
      if (!(e.line in m.evidence)) m.evidence[e.line] = e.text ?? null;
    }
    for (const n of f.lines) if (!m.lines.includes(n)) m.lines.push(n);
    m.lines.sort((a, b) => a - b);
    if (f.reason && !m.reasons.includes(f.reason) && m.reasons.length < 4) m.reasons.push(f.reason);
    if (f.action && !m.actions.includes(f.action) && m.actions.length < 2) m.actions.push(f.action);
    for (const n of f.notes || []) if (!m.notes.includes(n)) m.notes.push(n);
    if (chunkIndex != null && !m.chunks.includes(chunkIndex)) m.chunks.push(chunkIndex);
    if (!m.sources.includes(source)) m.sources.push(source);
    return m;
  }
  get(type, entity) {
    return this.items[`${type}|${entity}`];
  }
  all() {
    return Object.values(this.items);
  }
}

const fmtRange = (a) => (a.length > 3 ? `L${a[0]}, L${a[1]} … L${a[a.length - 1]}` : a.map((n) => `L${n}`).join(", "));

/**
 * Cross-part correlation over the whole file, using the ledger (facts from
 * every part) and the merged model findings. Links events that are far apart.
 */
export function correlate(store, ledger, chunkOfLine) {
  const partsOf = (lines) => [...new Set(lines.map(chunkOfLine))].sort((a, b) => a - b);
  for (const [ip, e] of Object.entries(ledger.ips)) {
    const fails = e.authFail;
    if (fails.length < 3) continue;
    const firstFail = fails[0];
    const successAfter = e.authOk.filter((n) => n > firstFail);
    const users = e.users.join(", ") || "unknown user";

    // Link all failed logins of this IP across the file into one brute-force finding.
    store.add(
      {
        attack_type: "Brute Force",
        entity: ip,
        severity: fails.length >= 5 ? "High" : "Medium",
        confidence: fails.length >= 5 ? "high" : "medium",
        lines: fails,
        evidence: fails.map((n) => ({ line: n })),
        reason: `${fails.length} failed logins for ${users} spread across parts ${partsOf(fails).map((p) => p + 1).join(", ")} (${fmtRange(fails)})`,
        action: DEFAULT_ACTIONS["Brute Force"],
      },
      null,
      "correlation"
    );

    if (successAfter.length) {
      const ok = successAfter[0];
      const after = [...new Set([...e.sensitive, ...e.bigResponses])].filter((n) => n > ok).sort((a, b) => a - b);
      const lines = [...new Set([...fails.slice(-3), ...successAfter, ...after])].sort((a, b) => a - b);
      store.add(
        {
          attack_type: "Account Compromise",
          entity: ip,
          severity: "Critical",
          confidence: "high",
          lines,
          evidence: lines.map((n) => ({ line: n })),
          reason:
            `${fails.length} failed logins (${fmtRange(fails)}) followed by a successful login at L${ok} from the same IP` +
            (after.length ? `, then sensitive activity at ${fmtRange(after)}` : ""),
          action: DEFAULT_ACTIONS["Account Compromise"],
        },
        null,
        "correlation"
      );
      if (e.bigResponses.some((n) => n > ok)) {
        const big = e.bigResponses.filter((n) => n > ok);
        store.add(
          {
            attack_type: "Data Exfiltration",
            entity: ip,
            severity: "Critical",
            confidence: "medium",
            lines: big,
            evidence: big.map((n) => ({ line: n })),
            reason: `Large download(s) at ${fmtRange(big)} after a login that followed ${fails.length} failures`,
            action: DEFAULT_ACTIONS["Data Exfiltration"],
          },
          null,
          "correlation"
        );
      }
    }
  }
}

/** Fill in text for evidence lines that came from other parts (streams the file once). */
export async function hydrateEvidence(store, filePath) {
  const need = new Set();
  for (const m of store.all()) for (const [n, t] of Object.entries(m.evidence)) if (t == null) need.add(Number(n));
  if (!need.size) return;
  const texts = new Map();
  for await (const ln of readLines(filePath)) {
    if (need.has(ln.lineNo)) texts.set(ln.lineNo, normalizeLine(ln.raw).text);
    if (texts.size === need.size) break;
  }
  for (const m of store.all()) for (const n of Object.keys(m.evidence)) if (m.evidence[n] == null) m.evidence[n] = texts.get(Number(n)) ?? "";
}

/** Build the final, de-duplicated report structure. */
export function buildReport(store, ledger, chunkOfLine) {
  const findings = store
    .all()
    .map((m, i) => {
      const lines = m.lines;
      return {
        id: i + 1,
        attack_type: m.attack_type,
        severity: m.severity,
        confidence: m.confidence,
        entity: m.entity,
        evidence_lines: lines,
        evidence: lines.slice(0, 12).map((n) => ({ line: n, text: m.evidence[n] ?? "" })),
        more_evidence: Math.max(0, lines.length - 12),
        first_line: lines[0],
        last_line: lines[lines.length - 1],
        parts: [...new Set(lines.map(chunkOfLine))].sort((a, b) => a - b).map((p) => p + 1),
        reason: m.reasons[m.reasons.length - 1] || m.reasons[0] || "",
        other_reasons: m.reasons.slice(0, -1),
        action: m.actions[0] || DEFAULT_ACTIONS[m.attack_type],
        notes: m.notes,
        sources: m.sources,
        times_reported: m.mentions,
      };
    })
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.first_line - b.first_line);
  findings.forEach((f, i) => (f.id = i + 1));

  // Incidents: everything known about one entity, in file order (attack chain).
  const byEntity = {};
  for (const f of findings) (byEntity[f.entity] ||= []).push(f);
  const incidents = Object.entries(byEntity)
    .map(([entity, fs]) => {
      const severity = fs.reduce((s, f) => maxSev(s, f.severity), "Low");
      const steps = fs
        .map((f) => ({ attack_type: f.attack_type, severity: f.severity, first_line: f.first_line, last_line: f.last_line, finding_id: f.id }))
        .sort((a, b) => a.first_line - b.first_line);
      const parts = [...new Set(fs.flatMap((f) => f.parts))].sort((a, b) => a - b);
      const led = ledger.ips[entity];
      return {
        entity,
        severity,
        attack_types: [...new Set(steps.map((s) => s.attack_type))],
        steps,
        parts,
        spans_multiple_parts: parts.length > 1,
        users: led?.users || [],
        total_requests: led?.requests ?? null,
      };
    })
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.steps.length - a.steps.length);

  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const f of findings) counts[f.severity]++;
  return { counts, findings, incidents };
}

export function fallbackSummary(report) {
  if (!report.findings.length) return "No suspicious activity was confirmed in this log.";
  const top = report.incidents.slice(0, 3).map((i) => `${i.entity} (${i.severity}: ${i.attack_types.join(" → ")})`);
  return `${report.findings.length} findings across ${report.incidents.length} sources. Most serious: ${top.join("; ")}.`;
}
