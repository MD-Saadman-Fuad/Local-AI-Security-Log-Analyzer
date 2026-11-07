// Turns one raw log line into (a) a compact text form that is sent to the model
// and (b) structured facts used by the cross-chunk ledger.
//
// Compaction is lossless for security-relevant fields and drops noise
// (request ids, host names, full browser UA strings), which roughly halves the
// tokens per line and therefore halves the number of model calls.
// The original line number is always kept ("L123") so evidence stays traceable.
import { CONFIG } from "./config.js";

const BROWSER_UA = /^Mozilla\/5\.0/;
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const AUTH_PATH = /(login|signin|sign-in|auth|session|token|wp-login|xmlrpc)/i;
// Apache/Nginx combined log format
const CLF =
  /^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?/;
// OpenSSH-style syslog auth lines
const SSH_FAIL = /Failed password for (?:invalid user )?(\S+) from (\S+)/i;
const SSH_OK = /Accepted (?:password|publickey) for (\S+) from (\S+)/i;

// Attack-looking content in a (decoded) path or free-text field.
const PAYLOAD = /('|"|\bunion\b|\bselect\b|sleep\(|\bor\s+1=1|\.\.\/|<script|etc\/passwd|\$\{|;\s*(ls|cat|wget|curl|rm)\b|\/\.(env|git|htaccess|aws)|wp-admin|wp-login|phpmyadmin|\/admin\b|actuator|server-status|\.(sql|bak|old)\b|\/config\.(json|php|ya?ml))/i;

/**
 * Does this line carry a security signal strong enough to support an attack
 * finding? A plain error status (422, 500, 503…) is NOT enough on its own:
 * ordinary application errors must not be reported as attacks. 401/403/429,
 * attack payloads, auth events, rate counters, big downloads, WAF rules and
 * free-text input are.
 */
function computeSignal(f, extraText) {
  return Boolean(
    f.status === 401 ||
      f.status === 403 ||
      f.status === 429 ||
      f.auth ||
      f.rate ||
      (f.bytes && f.bytes >= 1_000_000) ||
      f.securityRule ||
      extraText ||
      (f.path && PAYLOAD.test(decodePath(f.path)))
  );
}

// Fields that are shown in fixed positions or deliberately dropped.
const HANDLED = new Set([
  "time", "timestamp", "@timestamp", "app", "host", "service", "level", "client_ip",
  "ip", "remote_addr", "request_id", "method", "path", "url", "status", "response_bytes",
  "duration_ms", "user_agent", "username", "user", "auth_result", "session_id", "message",
  "security_rule", "requests_in_window", "window_seconds",
]);

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

// Decode URL encoding up to twice and say so if double encoding was used
// (a classic WAF-evasion trick that the model should see).
export function decodePath(p) {
  if (!p) return p;
  const once = safeDecode(p.replace(/\+/g, " "));
  if (/%[0-9a-f]{2}/i.test(once)) {
    const twice = safeDecode(once);
    if (twice !== once) return `${twice} [double-encoded]`;
  }
  return once;
}

const clip = (s, n) => (s.length > n ? s.slice(0, n) + "…" : s);
const q = (s, n = 100) => JSON.stringify(clip(String(s), n)); // quoted => clearly data

function shortTime(t) {
  if (!t) return "";
  const m = String(t).match(/T?(\d{2}:\d{2}:\d{2})(\.\d+)?/);
  if (!m) return clip(String(t), 25);
  return m[2] && !/^\.0+$/.test(m[2]) ? m[1] + m[2].slice(0, 2) : m[1];
}

function shortUa(ua) {
  if (!ua) return null;
  return BROWSER_UA.test(ua) ? "browser" : clip(ua, 32);
}

function authOutcome(f) {
  const r = String(f.auth_result || "").toLowerCase();
  if (r) return /success|ok|accepted/.test(r) ? "success" : "fail";
  if (f.path && AUTH_PATH.test(f.path) && f.method === "POST" && f.status) {
    if (f.status === 401 || f.status === 403) return "fail";
    if (f.status >= 200 && f.status < 300) return "success";
  }
  return null;
}

function fromJson(o) {
  const f = {
    ts: o.time || o.timestamp || o["@timestamp"] || null,
    ip: o.client_ip || o.ip || o.remote_addr || null,
    user: o.username || o.user || null,
    session: o.session_id || null,
    method: o.method || null,
    path: o.path || o.url || null,
    status: o.status != null ? Number(o.status) : null,
    level: o.level || null,
    service: o.service || null,
    bytes: o.response_bytes != null ? Number(o.response_bytes) : null,
    rate: o.requests_in_window != null ? Number(o.requests_in_window) : null,
    rateWindow: o.window_seconds != null ? Number(o.window_seconds) : null,
    requestId: o.request_id || null,
    securityRule: o.security_rule || null,
  };
  f.auth = authOutcome({ ...f, auth_result: o.auth_result });
  const extraText = Object.entries(o).some(([k, v]) => !HANDLED.has(k) && typeof v === "string" && v.length > 30);
  f.signal = computeSignal(f, extraText && !!f.ip); // free text counts only when a client sent it

  const parts = [shortTime(f.ts)];
  if (f.level && !/^info$/i.test(f.level)) parts.push(f.level.toUpperCase());
  if (f.service && f.service !== "gateway") parts.push(`svc=${f.service}`);
  if (f.ip) parts.push(f.ip);
  if (f.method || f.path) parts.push(`${f.method || ""} ${clip(decodePath(f.path || ""), 160)}`.trim());
  if (f.status != null) parts.push(String(f.status));
  if (f.user) parts.push(`user=${f.user}`);
  if (o.auth_result) parts.push(`auth=${o.auth_result}`);
  if (f.session) parts.push(`sess=${f.session}`);
  if (o.security_rule) parts.push(`rule=${o.security_rule}`);
  if (f.rate != null) parts.push(`rate=${f.rate}/${f.rateWindow || "?"}s`);
  if (f.bytes != null && f.bytes >= 1_000_000) parts.push(`bytes=${f.bytes}`);
  if (o.duration_ms != null && o.duration_ms >= 3000) parts.push(`dur=${o.duration_ms}ms`);
  const ua = shortUa(o.user_agent);
  if (ua) parts.push(`ua=${ua}`);
  if (o.message) parts.push(`msg=${q(o.message, 80)}`);
  for (const [k, v] of Object.entries(o)) {
    if (HANDLED.has(k) || v == null) continue;
    const val = typeof v === "string" ? q(v) : clip(JSON.stringify(v), 80);
    parts.push(`${k}=${val}`);
  }
  return { facts: f, text: parts.filter(Boolean).join(" ") };
}

function fromText(line) {
  let m = line.match(CLF);
  if (m) {
    const [, ip, user, ts, method, path, status, bytes, , ua] = m;
    const f = {
      ts, ip, user: user !== "-" ? user : null, session: null, method, path,
      status: Number(status), level: null, service: null,
      bytes: bytes === "-" ? null : Number(bytes), rate: null, rateWindow: null, requestId: null,
    };
    f.auth = authOutcome(f);
    f.signal = computeSignal(f, false);
    const parts = [shortTime(ts.replace(/^[^:]*:/, "T")), ip, method, clip(decodePath(path), 160), status];
    if (f.user) parts.push(`user=${f.user}`);
    if (f.bytes >= 1_000_000) parts.push(`bytes=${f.bytes}`);
    const sua = shortUa(ua);
    if (sua) parts.push(`ua=${sua}`);
    return { facts: f, text: parts.join(" ") };
  }
  const f = {
    ts: null, ip: (line.match(IPV4) || [null])[0], user: null, session: null, method: null,
    path: null, status: null, level: null, service: null, bytes: null, rate: null,
    rateWindow: null, requestId: null, auth: null,
  };
  if ((m = line.match(SSH_FAIL))) Object.assign(f, { user: m[1], ip: m[2], auth: "fail" });
  else if ((m = line.match(SSH_OK))) Object.assign(f, { user: m[1], ip: m[2], auth: "success" });
  // Unstructured text: can't tell clean from suspicious, so let the model decide.
  f.signal = true;
  return { facts: f, text: clip(line.replace(/\s+/g, " ").trim(), CONFIG.maxLineChars) };
}

/** Normalize one raw line. Never throws: malformed input degrades to plain text. */
export function normalizeLine(raw) {
  const line = raw.length > CONFIG.maxLineChars * 4 ? raw.slice(0, CONFIG.maxLineChars * 4) : raw;
  const trimmed = line.trim();
  if (trimmed.startsWith("{")) {
    try {
      return fromJson(JSON.parse(trimmed));
    } catch {
      /* fall through: truncated / invalid JSON line is treated as text */
    }
  }
  return fromText(trimmed);
}

// Multi-line entries (stack traces, wrapped messages) must stay in one chunk.
const CONTINUATION = /^(\s+\S|at\s|Caused by|\.\.\. \d+ more|Traceback|\s*File ")/;
export const isContinuation = (raw) => raw.length > 0 && CONTINUATION.test(raw);
