// Cross-chunk memory ("ledger").
//
// After each chunk, per-entity facts are accumulated here from the *parsed*
// fields of the log lines (never from free text) plus the attack types/severity
// the model already reported. Before the next call, the most relevant entries
// are rendered into a small "Known context" block that fits the memory budget.
//
// Because only counters, line numbers, IPs/usernames and enum values are
// stored, text injected into a log line can never propagate into later prompts.

const SEV_RANK = { Low: 1, Medium: 2, High: 3, Critical: 4 };
const MAX_REFS = 40; // line refs kept per list (first 20 + most recent 20)
const RATE_WINDOW_MS = 10_000;

function pushRef(arr, n) {
  arr.push(n);
  if (arr.length > MAX_REFS) arr.splice(MAX_REFS / 2, 1); // keep head and tail
}

const SAFE_IP = /^[0-9a-fA-F:.]{3,45}$/;
const safeName = (u) => String(u).replace(/[^\w.@-]/g, "").slice(0, 32) || null;

const SENSITIVE_PATH =/(admin|export|backup|config|\.env|\.git|passwd|actuator|phpmyadmin|wp-admin|server-status)/i;

export class Ledger {
  constructor(data) {
    this.ips = data?.ips || {};
    this.lastChunk = data?.lastChunk ?? -1;
    this.seenRequests = data?.seenRequests || []; // request ids already counted
  }

  toJSON() {
    return { ips: this.ips, lastChunk: this.lastChunk, seenRequests: this.seenRequests };
  }

  get(ip) {
    return (this.ips[ip] ||= {
      requests: 0,
      authFail: [],
      authOk: [],
      users: [],
      denied: [], // 401/403
      notFound: 0,
      clientErrors: 0,
      sensitive: [], // lines touching admin/export/config-like paths
      bigResponses: [],
      peakRate: 0, // max requests seen in any 10s window (or reported by the log)
      recent: [], // timestamps (ms) inside the sliding window
      firstLine: null,
      lastLine: null,
      flags: {}, // attackType -> severity (from validated model findings)
    });
  }

  /** Update from the parsed lines of a finished chunk. Idempotent per chunk. */
  ingest(chunkIndex, lines) {
    if (chunkIndex <= this.lastChunk) return;
    const seen = new Set(this.seenRequests);
    for (const { lineNo, facts: f } of lines) {
      // IPs and usernames are attacker-controlled log text: only IP-shaped keys
      // and short, character-restricted usernames may enter the prompt memory.
      if (!f.ip || !SAFE_IP.test(f.ip)) continue;
      // The same request logged twice (duplicate line) is counted once.
      if (f.requestId) {
        if (seen.has(f.requestId)) continue;
        seen.add(f.requestId);
      }
      const e = this.get(f.ip);
      e.requests++;
      e.firstLine ??= lineNo;
      e.lastLine = lineNo;
      const user = f.user && safeName(f.user);
      if (user && !e.users.includes(user) && e.users.length < 5) e.users.push(user);
      if (f.auth === "fail") pushRef(e.authFail, lineNo);
      if (f.auth === "success") pushRef(e.authOk, lineNo);
      if (f.status === 401 || f.status === 403) pushRef(e.denied, lineNo);
      if (f.status === 404) e.notFound++;
      if (f.status >= 400 && f.status < 500) e.clientErrors++;
      if (f.path && SENSITIVE_PATH.test(f.path)) pushRef(e.sensitive, lineNo);
      if (f.bytes >= 1_000_000) pushRef(e.bigResponses, lineNo);
      if (f.rate) e.peakRate = Math.max(e.peakRate, f.rate);
      const t = Date.parse(f.ts);
      if (!Number.isNaN(t)) {
        e.recent = e.recent.filter((x) => t - x < RATE_WINDOW_MS);
        e.recent.push(t);
        e.peakRate = Math.max(e.peakRate, e.recent.length);
      }
    }
    this.seenRequests = [...seen].slice(-2000);
    this.lastChunk = chunkIndex;
  }

  /** Record a validated model finding so later chunks know about it. */
  flag(ip, attackType, severity) {
    if (!this.ips[ip]) return;
    const prev = this.ips[ip].flags[attackType];
    if (!prev || SEV_RANK[severity] > SEV_RANK[prev]) this.ips[ip].flags[attackType] = severity;
  }

  /** How interesting is an entity, for choosing what fits in the memory budget. */
  score(e) {
    let s = e.authFail.length * 3 + e.denied.length * 2 + e.sensitive.length * 2 + e.bigResponses.length * 3;
    if (e.peakRate >= 20) s += 10;
    for (const sev of Object.values(e.flags)) s += SEV_RANK[sev] * 5;
    if (e.authFail.length && e.authOk.length) s += 20;
    return s;
  }

  /**
   * Render "Known context" lines for the next chunk, most relevant first:
   * entities that also appear in the next chunk, then the highest scoring rest.
   * `countTokens` + `budget` keep the block within the memory budget.
   */
  render(nextChunkIps, countTokens, budget) {
    const fmtRefs = (a) =>
      a.length <= 4 ? a.map((n) => `L${n}`).join(",") : `L${a[0]},L${a[1]}…L${a[a.length - 1]}`;
    const describe = (ip, e) => {
      const bits = [];
      if (e.users.length) bits.push(`user=${e.users.join("/")}`);
      if (e.authFail.length) bits.push(`${e.authFail.length} failed logins (${fmtRefs(e.authFail)})`);
      if (e.authOk.length) bits.push(`${e.authOk.length} successful logins (${fmtRefs(e.authOk)})`);
      const otherDenied = e.denied.length - e.authFail.length;
      if (otherDenied > 0) bits.push(`${otherDenied} other 401/403`);
      if (e.notFound >= 2) bits.push(`${e.notFound}x 404`);
      if (e.sensitive.length) bits.push(`sensitive paths (${fmtRefs(e.sensitive)})`);
      if (e.bigResponses.length) bits.push(`large downloads (${fmtRefs(e.bigResponses)})`);
      if (e.peakRate >= 20) bits.push(`peak ${e.peakRate} req/10s`);
      const flags = Object.entries(e.flags).map(([t, s]) => `${t}/${s}`);
      if (flags.length) bits.push(`already reported: ${flags.join(", ")}`);
      return bits.length ? `- ${ip}: ${bits.join("; ")}` : null;
    };

    const candidates = Object.entries(this.ips)
      .filter(([, e]) => this.score(e) > 0)
      .map(([ip, e]) => ({ ip, e, rel: (nextChunkIps.has(ip) ? 1000 : 0) + this.score(e) }))
      .sort((a, b) => b.rel - a.rel);

    const out = [];
    let used = 0;
    for (const { ip, e } of candidates) {
      const line = describe(ip, e);
      if (!line) continue;
      const t = countTokens(line) + 1;
      if (used + t > budget) continue; // try smaller ones that may still fit
      out.push(line);
      used += t;
    }
    return { text: out.join("\n"), tokens: used, entities: out.length };
  }
}
