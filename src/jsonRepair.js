// Tolerant JSON parsing for model output.
// Order of attempts:
//   1. strict JSON.parse
//   2. strip markdown fences / <think> blocks / prose around the outermost {...}
//   3. repair truncation: close open strings/arrays/objects, drop dangling
//      partial key/values and trailing commas
//   4. salvage: extract every complete {...} object inside "findings": [...]
// Never throws; returns { ok, value, repaired, error }.

function stripNoise(s) {
  return s
    .replace(/<think>[\s\S]*?<\/think>/gi, "")
    .replace(/<think>[\s\S]*$/i, "") // unterminated thinking block
    .replace(/```(?:json)?/gi, "")
    .trim();
}

/** Close whatever is still open after a truncated generation. */
export function closeTruncated(s) {
  const stack = [];
  let inStr = false;
  let esc = false;
  let lastSafe = 0; // index just after the last complete value boundary
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === "{" || c === "[") stack.push(c);
    else if (c === "}" || c === "]") {
      stack.pop();
      lastSafe = i + 1;
    } else if (c === ",") lastSafe = i;
  }
  if (!inStr && stack.length === 0) return s;
  // Cut back to the last point where a value was complete, then close brackets.
  let cut = s.slice(0, lastSafe).replace(/[,:\s]+$/, "");
  const st = [];
  let str = false;
  let e = false;
  for (const c of cut) {
    if (str) {
      if (e) e = false;
      else if (c === "\\") e = true;
      else if (c === '"') str = false;
      continue;
    }
    if (c === '"') str = true;
    else if (c === "{" || c === "[") st.push(c);
    else if (c === "}" || c === "]") st.pop();
  }
  while (st.length) cut += st.pop() === "{" ? "}" : "]";
  return cut;
}

function tryParse(s) {
  try {
    return { ok: true, value: JSON.parse(s) };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

function salvageObjects(s) {
  const found = [];
  const start = s.indexOf("[");
  if (start === -1) return found;
  let depth = 0;
  let objStart = -1;
  let inStr = false;
  let esc = false;
  for (let i = start + 1; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === "{") {
      if (depth === 0) objStart = i;
      depth++;
    } else if (c === "}") {
      depth--;
      if (depth === 0 && objStart !== -1) {
        const r = tryParse(s.slice(objStart, i + 1));
        if (r.ok) found.push(r.value);
        objStart = -1;
      }
    }
  }
  return found;
}

export function parseModelJson(text) {
  if (typeof text !== "string" || !text.trim()) return { ok: false, error: "empty output" };
  let r = tryParse(text);
  if (r.ok) return { ok: true, value: r.value, repaired: false };

  let s = stripNoise(text);
  // Seen with Qwen3.5 + grammar + forced end-of-thought: the opening brace is swallowed.
  if (/^\s*"\w+"\s*:/.test(s)) s = "{" + s;
  const first = s.indexOf("{");
  if (first === -1) return { ok: false, error: "no JSON object in output" };
  s = s.slice(first);
  const last = s.lastIndexOf("}");
  if (last !== -1) {
    r = tryParse(s.slice(0, last + 1).replace(/,\s*([}\]])/g, "$1"));
    if (r.ok) return { ok: true, value: r.value, repaired: true };
  }
  r = tryParse(closeTruncated(s).replace(/,\s*([}\]])/g, "$1"));
  if (r.ok) return { ok: true, value: r.value, repaired: true };

  const objs = salvageObjects(s);
  if (objs.length) return { ok: true, value: { findings: objs }, repaired: true };
  return { ok: false, error: r.error };
}
