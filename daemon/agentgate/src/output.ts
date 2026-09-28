/**
 * Minimal terminal output. Status lines go to stderr so the wrapped command's
 * stdout stays clean for pipes. Colors only when stderr is a TTY and NO_COLOR is unset.
 */

const useColor = (stream: NodeJS.WriteStream) =>
  Boolean(stream.isTTY) && !process.env.NO_COLOR && process.env.TERM !== "dumb";

const wrap = (code: number, reset: number) => (s: string) =>
  useColor(process.stderr) ? `\x1b[${code}m${s}\x1b[${reset}m` : s;

export const c = {
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  magenta: wrap(35, 39),
  cyan: wrap(36, 39),
  gray: wrap(90, 39),
};

let verbose = false;
let sink: ((line: string) => void) | null = null;
/** Redirect all status/debug lines (e.g. to a log file in hook mode). */
export function setSink(fn: ((line: string) => void) | null) {
  sink = fn;
}
function emit(line: string) {
  if (sink) sink(line);
  else process.stderr.write(`${line}\n`);
}
export function setVerbose(v: boolean) {
  verbose = v;
}
export function isVerbose() {
  return verbose;
}

const PREFIX = () => c.magenta("agentgate");

export const log = {
  step(msg: string) {
    emit(`${PREFIX()} ${msg}`);
  },
  ok(msg: string) {
    emit(`${PREFIX()} ${c.green("✔")} ${msg}`);
  },
  warn(msg: string) {
    emit(`${PREFIX()} ${c.yellow("!")} ${msg}`);
  },
  fail(msg: string) {
    emit(`${PREFIX()} ${c.red("✖")} ${msg}`);
  },
  debug(msg: string, data?: unknown) {
    if (!verbose) return;
    const extra = data === undefined ? "" : ` ${redactJson(data)}`;
    emit(c.gray(`[debug] ${redactString(msg)}${extra}`));
  },
};

/** stdout, for command results (config/status output). */
export function out(line = "") {
  process.stdout.write(`${line}\n`);
}

// ── Redaction ───────────────────────────────────────────────────────────────

const SENSITIVE_KEYS = /^(authorization|access_token|refresh_token|approval_token|token|password|secret|private_key)$/i;

/** Redacts bearer tokens, approval tokens and `access_token=` query params. */
export function redactString(s: string): string {
  return s
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[REDACTED]")
    .replace(/(access_token=)[^&\s]+/gi, "$1[REDACTED]")
    .replace(/\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}\b/g, "[REDACTED_TOKEN]")
    .replace(/\bagr_[A-Za-z0-9_-]{16,}/g, "agr_[REDACTED]");
}

export function redact<T>(value: T): T {
  if (typeof value === "string") return redactString(value) as T;
  if (Array.isArray(value)) return value.map((v) => redact(v)) as T;
  if (value && typeof value === "object") {
    const outObj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      outObj[k] = SENSITIVE_KEYS.test(k) && v != null ? "[REDACTED]" : redact(v);
    }
    return outObj as T;
  }
  return value;
}

function redactJson(data: unknown): string {
  try {
    return JSON.stringify(redact(data));
  } catch {
    return "[unserializable]";
  }
}
