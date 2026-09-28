/**
 * Does the command's exit status hide earlier failures?
 *
 * `/bin/sh -c` (like every shell) returns the status of the LAST command it ran. For
 * `a && b` that is faithful, but for a `;`-, newline- or `&`-separated list
 * (`git push; git log -1`) an earlier failure is masked by a later success. AgentGate
 * must not change the command (the hash binds it), so we report the true exit status
 * and annotate the audit when it may mask a failure.
 *
 * Returns true if an unquoted top-level `;`, `&` (not `&&`, not a redirection) or
 * newline separates commands. Quotes, `$(…)`/backticks, `(…)`/`{…}` groups and heredoc
 * bodies are skipped. Heuristic, informational only — never used for decisions.
 */
export function masksEarlierFailures(command: string): boolean {
  let depth = 0; // $( ( {
  let quote: "'" | '"' | "`" | null = null;
  const pendingHeredocs: Array<{ delim: string; strip: boolean }> = [];
  let sawCommand = false;

  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!;
    const next = command[i + 1];

    if (quote) {
      if (ch === "\\" && quote !== "'") i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "\\") {
      i++;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      quote = ch;
      sawCommand = true;
      continue;
    }
    if (ch === "#" && (i === 0 || /\s/.test(command[i - 1]!))) {
      while (i < command.length && command[i] !== "\n") i++;
      i--;
      continue;
    }
    if ((ch === "$" && next === "(") || ch === "(" || (ch === "{" && (next === " " || next === "\n"))) {
      depth++;
      if (ch === "$") i++;
      continue;
    }
    if ((ch === ")" || ch === "}") && depth > 0) {
      depth--;
      continue;
    }
    if (ch === "<" && next === "<" && command[i + 2] !== "<") {
      const m = /^<<(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/.exec(command.slice(i));
      if (m) {
        pendingHeredocs.push({ delim: m[3]!, strip: m[1] === "-" });
        i += m[0].length - 1;
        continue;
      }
    }
    if (ch === "\n") {
      if (pendingHeredocs.length) {
        // skip heredoc bodies
        let pos = i + 1;
        for (const h of pendingHeredocs.splice(0)) {
          for (;;) {
            const end = command.indexOf("\n", pos);
            const line = command.slice(pos, end === -1 ? undefined : end);
            pos = end === -1 ? command.length : end + 1;
            if ((h.strip ? line.replace(/^\t+/, "") : line) === h.delim || end === -1) break;
          }
        }
        i = pos - 1;
        if (depth === 0 && sawCommand && command.slice(pos).trim()) return true;
        continue;
      }
      if (depth === 0 && sawCommand && command.slice(i + 1).trim() && !/(&&|\|\||\||\\)\s*$/.test(command.slice(0, i))) return true;
      continue;
    }
    if (depth === 0 && ch === ";" && next !== ";" && command.slice(i + 1).trim()) return true;
    if (depth === 0 && ch === "&" && next !== "&" && command[i - 1] !== "&" && command[i - 1] !== ">" && next !== ">") {
      if (command.slice(i + 1).trim()) return true;
    }
    if (!/\s/.test(ch)) sawCommand = true;
  }
  return false;
}

export const MASKED_STATUS_NOTE =
  "exit status is that of the last command in a ;/newline/&-separated list — earlier commands may have failed";
