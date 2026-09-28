/**
 * Minimal shell command analysis. We do not try to be a full POSIX parser; we only
 * need to (a) split compound commands so every sub-command is judged on its own, and
 * (b) flag constructs we cannot statically see through, so they are never auto-allowed.
 */

export interface ShellAnalysis {
  /** Sub-commands split on ; && || | & and newlines (outside quotes), trimmed. */
  segments: string[];
  /** True if the command contains substitution/eval-like constructs. */
  opaque: boolean;
  opaqueReason: string | null;
}

export function analyzeShell(command: string): ShellAnalysis {
  const segments: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;
  let opaqueReason: string | null = null;

  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!;
    const next = command[i + 1];

    if (quote) {
      if (ch === "\\" && quote === '"' && next !== undefined) {
        current += ch + next;
        i++;
        continue;
      }
      if (quote === '"' && (ch === "`" || (ch === "$" && next === "("))) {
        opaqueReason ??= "command substitution";
      }
      if (ch === quote) quote = null;
      current += ch;
      continue;
    }

    if (ch === "\\" && next !== undefined) {
      current += ch + next;
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === "`" || (ch === "$" && next === "(")) opaqueReason ??= "command substitution";
    if ((ch === "<" || ch === ">") && next === "(") opaqueReason ??= "process substitution";

    const two = ch + (next ?? "");
    if (two === "&&" || two === "||") {
      pushSegment(segments, current);
      current = "";
      i++;
      continue;
    }
    // `(`/`)` (subshells, $(...), <(...)) and backticks also delimit commands: splitting on
    // them means the *inner* command is judged on its own (`(rm -rf /)` is `rm -rf /`).
    if (
      ch === ";" || ch === "|" || ch === "\n" || ch === "(" || ch === ")" || ch === "`" ||
      (ch === "&" && next !== ">" && command[i - 1] !== ">")
    ) {
      pushSegment(segments, current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (quote) opaqueReason ??= "unbalanced quotes";
  pushSegment(segments, current);

  for (const seg of segments) {
    opaqueReason ??= opaqueSegmentReason(seg);
  }

  return { segments, opaque: opaqueReason !== null, opaqueReason };
}

const SHELL_RE = /^(ba|z|da|k|c|tc|mk|a|fi)?sh$|^fish$/;
const INTERPRETER_RE = /^(python[0-9.]*|node|nodejs|perl|ruby|php|lua|deno|bun|osascript|pwsh|powershell)$/;
const INLINE_CODE_FLAGS = new Set(["-c", "-e", "-E", "-r", "-p", "--eval", "--print", "--command", "-Command", "eval", "-"]);
const AWK_RE = /^(awk|gawk|mawk|nawk)$/;
const EDITOR_RE = /^(vi|vim|nvim|view|ex|gvim|mvim|emacs|nano)$/;
const PAGER_RE = /^(less|more|most|man)$/;

/** awk programs can run commands via system(), `cmd | getline` and `print | "cmd"`. */
function awkRunsCommands(args: string[]): boolean {
  let skipNext = false;
  for (const a of args) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (a === "-F" || a === "-v") {
      skipNext = true;
      continue;
    }
    if (a.startsWith("-F") || a.startsWith("-v")) continue;
    if (/\bsystem\s*\(/.test(a) || a.includes("|")) return true;
  }
  return false;
}

/**
 * Environment variables whose value is executed (or loaded as code) by the command
 * they are passed to. A few well-known harmless values are tolerated.
 */
const EXEC_VARS = new Set([
  "LESSOPEN", "LESSCLOSE", "PAGER", "GIT_PAGER", "MANPAGER", "EDITOR", "VISUAL", "GIT_EDITOR",
  "GIT_SEQUENCE_EDITOR", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_ASKPASS", "SSH_ASKPASS",
  "GIT_EXEC_PATH", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "LD_PRELOAD", "LD_AUDIT",
  "DYLD_INSERT_LIBRARIES", "BASH_ENV", "ENV", "PROMPT_COMMAND", "PERL5OPT", "RUBYOPT", "PYTHONSTARTUP",
]);
const SAFE_EXEC_VALUES = new Set(["", "true", ":", "cat", "less", "less -R", "less -FRX", "more", "vi", "vim", "nvim", "nano"]);

function codeInjectingAssignment(name: string, value: string): string | null {
  if (name === "NODE_OPTIONS") {
    return /(^|\s)(-r|--require|--import|--loader|--experimental-loader)(\s|=|$)/.test(value)
      ? "NODE_OPTIONS preloads code"
      : null;
  }
  if (name === "PATH") {
    // Appending is fine (only adds new names); prepending can shadow any command.
    return /^\$\{?PATH\}?(:|$)/.test(value) ? null : "PATH prepended: commands may resolve to other programs";
  }
  if (name.startsWith("GIT_CONFIG_KEY_") || name.startsWith("GIT_CONFIG_VALUE_")) return `${name} injects git config`;
  if (!EXEC_VARS.has(name)) return null;
  if (SAFE_EXEC_VALUES.has(value.trim())) return null;
  if ((name === "GIT_SSH_COMMAND" || name === "GIT_SSH") && /^ssh(\s+[\w./=~@:,+-]+)*$/.test(value.trim())) return null;
  return `${name} runs a program chosen by the command line`;
}

/** Binaries whose arguments may be `$VAR` without changing *which* program/sub-command runs. */
const DYNAMIC_ARG_OK = new Set(["echo", "printf", "cat", "ls", "cd", "test", "[", "grep", "egrep", "fgrep", "rg", "head", "tail", "wc", "stat", "file", "printenv", "awk", "gawk", "mawk", "nawk", "sed", "jq", "export"]);

/**
 * Why a single segment cannot be statically judged, or null. Uses the *effective* argv so
 * wrappers (`sudo bash -c`, `env sh -c`, `FOO=1 eval`) and absolute paths (`/bin/sh -c`)
 * do not hide the construct.
 */
function opaqueSegmentReason(seg: string): string | null {
  const raw = tokenize(seg);
  const { start, argv: words, assignments } = unwrap(raw);
  const bin = words[0] ?? "";
  const args = words.slice(1);
  const isInfo = args.length > 0 && args.every((w) => ["--version", "-V", "--help", "-h"].includes(w));

  // `env -S "cmd args"` re-splits a string into a command line.
  const envAt = raw.slice(0, start).findIndex((w) => basename(w) === "env");
  if (envAt >= 0 && raw.slice(envAt + 1, start).some((w) => /^-[a-zA-Z]*S/.test(w) || w.startsWith("--split-string"))) {
    return "env -S builds a command from a string";
  }
  for (const [name, value] of assignments) {
    const why = codeInjectingAssignment(name, value);
    if (why) return why;
  }
  if (AWK_RE.test(bin) && awkRunsCommands(args)) return "awk program runs shell commands";
  if (["export", "declare", "typeset", "readonly", "local"].includes(bin)) {
    for (const a of args) {
      const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(a);
      const why = m ? codeInjectingAssignment(m[1]!, m[2]!) : null;
      if (why) return why;
    }
  }
  if (EDITOR_RE.test(bin) && args.some((a) => a.startsWith("+") || ["-c", "--cmd", "-S", "--eval", "-l", "--load", "-x", "--script"].includes(a) || a.startsWith("--eval="))) {
    return "editor command-line escape";
  }
  if (PAGER_RE.test(bin) && args.some((a) => a.startsWith("+") || a.startsWith("--pager") || a === "-P")) {
    return "pager command escape";
  }
  if (bin === "tar" || bin === "gtar" || bin === "bsdtar") {
    if (args.some((a) => /^--(checkpoint-action|to-command|use-compress-program|info-script|new-volume-script|rsh-command)/.test(a) || /^-[a-zA-Z]*[IF]/.test(a))) {
      return "tar option runs a program";
    }
  }
  if (bin === "zip" && args.some((a) => a === "-TT" || a.startsWith("--unzip-command"))) return "zip -TT runs a program";
  if (["ssh", "scp", "sftp"].includes(bin) && optionValues(args, ["-o"], []).some((v) => /^(ProxyCommand|LocalCommand|PermitLocalCommand|KnownHostsCommand)/i.test(v))) {
    return "ssh option runs a local command";
  }
  if (/[$*?[\]{}~]/.test(bin) && bin !== "[") return "dynamic command name";
  if (/\$/.test(args[0] ?? "") && !DYNAMIC_ARG_OK.has(bin)) return "dynamic sub-command";
  if (["eval", "source", "."].includes(bin)) return `${bin} of dynamic code`;
  if ((SHELL_RE.test(bin) || INTERPRETER_RE.test(bin)) && args.some((w) => w.startsWith("<<"))) {
    return "here-doc / here-string fed to an interpreter";
  }
  if (SHELL_RE.test(bin) && !isInfo) {
    const positional = args.filter((w) => !w.startsWith("-"));
    if (args.some((w) => /^-[a-zA-Z]*c[a-zA-Z]*$/.test(w))) return "nested shell -c";
    if (positional.length === 0 || args.includes("-s")) return "shell reading commands from stdin";
  }
  if (INTERPRETER_RE.test(bin) && !isInfo) {
    const positional = args.filter((w) => !w.startsWith("-"));
    if (args.some((w) => INLINE_CODE_FLAGS.has(w) || /^-[a-zA-Z]*[ce]$/.test(w))) return "inline interpreter code";
    if (positional.length === 0) return "interpreter reading code from stdin";
  }
  if (bin === "xargs") return "xargs builds commands dynamically";
  if (bin === "find" && args.some((w) => ["-exec", "-execdir", "-ok", "-okdir"].includes(w))) {
    return "find -exec runs commands dynamically";
  }
  if (bin === "git") {
    // `git -c core.pager=… status` etc. can execute arbitrary programs.
    for (let i = start + 1; i < raw.length && raw[i]!.startsWith("-"); i++) {
      const w = raw[i]!;
      if (w === "-c" || w.startsWith("--config-env") || w.startsWith("--exec-path=")) {
        return "git -c/--config-env can run arbitrary programs";
      }
      if (GIT_ARG_OPTS.has(w)) i++;
    }
  }
  return null;
}

function pushSegment(out: string[], seg: string) {
  const s = seg.trim();
  if (s) out.push(s);
}

/** Whitespace tokenization with quote removal. Good enough for prefix matching. */
export function tokenize(segment: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: "'" | '"' | null = null;
  let has = false;
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i]!;
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      has = true;
      continue;
    }
    if (ch === "\\" && i + 1 < segment.length) {
      cur += segment[++i];
      has = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (has || cur) out.push(cur);
      cur = "";
      has = false;
      continue;
    }
    cur += ch;
    has = true;
  }
  if (has || cur) out.push(cur);
  return out;
}

/**
 * Wrappers that don't change *what* runs, with the options that consume a separate
 * value (`sudo -u root`, `nice -n 10`) and the number of leading positional operands
 * (`timeout 5 cmd`).
 */
const WRAPPERS: Record<string, { argOpts: string[]; positionals?: number }> = {
  sudo: { argOpts: ["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T", "--user", "--group", "--chdir", "--host", "--prompt", "--role", "--type", "--other-user", "--command-timeout", "--close-from"] },
  doas: { argOpts: ["-u", "-C"] },
  env: { argOpts: ["-u", "-C", "--unset", "--chdir"] },
  command: { argOpts: [] },
  builtin: { argOpts: [] },
  time: { argOpts: ["-f", "-o", "--format", "--output"] },
  nohup: { argOpts: [] },
  exec: { argOpts: ["-a"] },
  nice: { argOpts: ["-n", "--adjustment"] },
  ionice: { argOpts: ["-c", "-n", "-p", "--class", "--classdata"] },
  stdbuf: { argOpts: ["-i", "-o", "-e", "--input", "--output", "--error"] },
  timeout: { argOpts: ["-s", "-k", "--signal", "--kill-after"], positionals: 1 },
  caffeinate: { argOpts: ["-t", "-w"] },
};

/** Shell reserved words that may precede a simple command (`if git push; then …`). */
const RESERVED = new Set(["!", "{", "}", "if", "then", "else", "elif", "fi", "do", "done", "while", "until"]);

/** git global options that take a separate value (`git -C dir push`). */
const GIT_ARG_OPTS = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--list-cmds", "--attr-source"]);

/** Last path component: `/usr/bin/git` → `git`. */
function basename(word: string): string {
  const i = word.lastIndexOf("/");
  return i >= 0 && i < word.length - 1 ? word.slice(i + 1) : word;
}

/**
 * The argv that actually determines what runs. Strips redirections (`> out`, `2>&1`),
 * leading VAR=value assignments, shell reserved words (`!`, `{`, `then`, `do`…), wrappers
 * (`sudo`, `env`, `nice`, `timeout`, …, including their options) and git global options
 * (`git -C dir push` → `git push`). The command name is reduced to its basename
 * (`/bin/rm` → `rm`).
 */
export function effectiveArgv(segment: string): string[] {
  return parseSegment(segment).argv;
}

/** A single simple command, decomposed. */
export interface ParsedSegment {
  /** Effective argv (see effectiveArgv). */
  argv: string[];
  /** Wrapper chain that was stripped, as basenames, outermost first (`sudo env nice`). */
  wrappers: string[];
  /** Leading NAME=value assignments, including those given to `env`. */
  assignments: Array<[name: string, value: string]>;
  /**
   * Paths this command writes to (raw, not normalized): output redirections plus the
   * destinations of tee, dd of=, cp, mv, install, ln, touch, mkdir, truncate, sed -i,
   * chmod/chown, sort -o, uniq, rsync, curl -o, wget -O, crontab.
   */
  writes: string[];
  /** Paths this command removes (rm, rmdir, unlink, shred, mv sources, find -delete roots, rsync --delete). */
  deletes: string[];
}

export function parseSegment(segment: string): ParsedSegment {
  const { command, writes } = parseRedirections(segment);
  const u = unwrap(tokenize(command));
  const fx = commandFileEffects(u.argv);
  return {
    argv: u.argv,
    wrappers: u.wrappers,
    assignments: u.assignments,
    writes: [...writes, ...fx.writes],
    deletes: fx.deletes,
  };
}

interface Unwrapped {
  /** Index in `words` of the effective command word. */
  start: number;
  argv: string[];
  wrappers: string[];
  assignments: Array<[string, string]>;
}

function unwrap(words: string[]): Unwrapped {
  const wrappers: string[] = [];
  const assignments: Array<[string, string]> = [];
  let i = 0;
  while (i < words.length) {
    const w = words[i]!;
    const assign = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(w);
    if (assign) {
      assignments.push([assign[1]!, assign[2]!]);
      i++;
      continue;
    }
    if (RESERVED.has(w)) {
      i++;
      continue;
    }
    const b = basename(w);
    // `command -v x` / `command -V x` is a lookup, not a wrapper.
    const isLookup = b === "command" && (words[i + 1] === "-v" || words[i + 1] === "-V");
    const wrapper = !isLookup && Object.hasOwn(WRAPPERS, b) ? WRAPPERS[b] : undefined;
    if (wrapper) {
      wrappers.push(b);
      i++;
      while (i < words.length && words[i]!.startsWith("-") && words[i] !== "-") {
        const opt = words[i]!;
        i++;
        if (opt === "--") break;
        if (wrapper.argOpts.includes(opt)) i++;
      }
      // env accepts assignments after its options; handled by the outer loop.
      i += wrapper.positionals ?? 0;
      continue;
    }
    break;
  }
  const argv = words.slice(i);
  const base = { start: i, wrappers, assignments };
  if (argv.length === 0) return { ...base, argv };
  argv[0] = basename(argv[0]!);
  if (argv[0] === "git") {
    let j = 1;
    while (j < argv.length && argv[j]!.startsWith("-")) {
      j += GIT_ARG_OPTS.has(argv[j]!) ? 2 : 1;
    }
    return { ...base, argv: ["git", ...argv.slice(j)] };
  }
  return { ...base, argv };
}

/**
 * Remove redirections from a segment (quote-aware) and collect output-redirection
 * targets. Handles `>`, `>>`, `>|`, `N>`, `&>`, `&>>`, `<>`; fd duplications (`2>&1`,
 * `>&-`) have no target; input redirections (`<`, `<<`, `<<<`) are dropped.
 */
export function parseRedirections(segment: string): { command: string; writes: string[] } {
  let out = "";
  const writes: string[] = [];
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i]!;
    if (quote) {
      if (ch === "\\" && quote === '"' && i + 1 < segment.length) {
        out += ch + segment[++i];
        continue;
      }
      if (ch === quote) quote = null;
      out += ch;
      continue;
    }
    if (ch === "\\" && i + 1 < segment.length) {
      out += ch + segment[++i];
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      out += ch;
      continue;
    }
    if (ch !== ">" && ch !== "<") {
      out += ch;
      continue;
    }
    // An fd number or `&` directly before the operator belongs to it (`2>`, `&>`).
    const fd = /(^|\s)(\d+|&)$/.exec(out);
    if (fd) out = out.slice(0, out.length - fd[2]!.length);
    let isOutput = ch === ">";
    let j = i + 1;
    if (ch === "<" && segment[j] === ">") isOutput = true;
    while (segment[j] === ">" || segment[j] === "<" || segment[j] === "|") j++;
    if (segment[j] === "&") {
      j++;
      if (/[0-9-]/.test(segment[j] ?? "")) {
        while (/[0-9-]/.test(segment[j] ?? "")) j++;
        out += " ";
        i = j - 1;
        continue;
      }
    }
    while (/\s/.test(segment[j] ?? "")) j++;
    const wordStart = j;
    let q: string | null = null;
    while (j < segment.length) {
      const c = segment[j]!;
      if (q) {
        if (c === q) q = null;
        j++;
        continue;
      }
      if (c === "'" || c === '"') {
        q = c;
        j++;
        continue;
      }
      if (c === "\\") {
        j += 2;
        continue;
      }
      if (/\s/.test(c) || c === ">" || c === "<") break;
      j++;
    }
    const target = tokenize(segment.slice(wordStart, j))[0];
    if (isOutput && target) writes.push(target);
    out += " ";
    i = j - 1;
  }
  return { command: out, writes };
}

/** Positional operands of argv[1..], skipping options (and the values of `argOpts`). */
function operands(args: string[], argOpts: string[] = []): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") {
      out.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith("-") && a !== "-") {
      if (argOpts.includes(a)) i++;
      continue;
    }
    out.push(a);
  }
  return out;
}

/** Value of `-o X`, `-oX` (short) or `--output X`, `--output=X` (long). */
function optionValues(args: string[], short: string[], long: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") break;
    for (const l of long) {
      if (a === l && args[i + 1] !== undefined) out.push(args[i + 1]!);
      else if (a.startsWith(`${l}=`)) out.push(a.slice(l.length + 1));
    }
    for (const sh of short) {
      if (a === sh && args[i + 1] !== undefined) out.push(args[i + 1]!);
      else if (a.startsWith(sh) && !a.startsWith("--") && a.length > sh.length) out.push(a.slice(sh.length));
    }
  }
  return out;
}

/** Files written / removed by common commands (argv already unwrapped; raw paths). */
function commandFileEffects(argv: string[]): { writes: string[]; deletes: string[] } {
  const [bin = "", ...args] = argv;
  const none = { writes: [] as string[], deletes: [] as string[] };
  const lastOf = (p: string[]) => (p.length >= 2 ? [p[p.length - 1]!] : []);
  const targetDir = () => {
    const t = optionValues(args, ["-t"], ["--target-directory"]);
    return t.length ? t : null;
  };
  switch (bin) {
    case "tee":
      return { writes: operands(args), deletes: [] };
    case "dd":
      return { writes: args.filter((a) => a.startsWith("of=")).map((a) => a.slice(3)), deletes: [] };
    case "cp":
    case "install":
    case "ln": {
      const t = targetDir();
      if (t) return { writes: t, deletes: [] };
      return { writes: lastOf(operands(args, ["-S", "--suffix", "-m", "--mode", "-o", "--owner", "-g", "--group"])), deletes: [] };
    }
    case "mv": {
      const ops = operands(args, ["-S", "--suffix"]);
      const t = targetDir();
      if (t) return { writes: t, deletes: ops };
      return ops.length >= 2 ? { writes: [ops[ops.length - 1]!], deletes: ops.slice(0, -1) } : none;
    }
    case "touch":
      return { writes: operands(args, ["-r", "-d", "-t", "--reference", "--date"]), deletes: [] };
    case "mkdir":
      return { writes: operands(args, ["-m", "--mode"]), deletes: [] };
    case "truncate":
      return { writes: operands(args, ["-s", "-r", "--size", "--reference"]), deletes: [] };
    case "chmod":
    case "chown":
    case "chgrp": {
      const ops = operands(args, ["--reference"]);
      return { writes: args.some((a) => a.startsWith("--reference")) ? ops : ops.slice(1), deletes: [] };
    }
    case "sed": {
      const inPlace = args.some((a) => /^-[a-zA-Z]*i/.test(a) && !a.startsWith("--") || a.startsWith("--in-place"));
      if (!inPlace) return none;
      const ops = operands(args, ["-e", "-f", "--expression", "--file", "-l", "--line-length"]);
      const scripted = args.some((a) => ["-e", "-f", "--expression", "--file"].includes(a) || a.startsWith("--expression=") || a.startsWith("--file="));
      return { writes: scripted ? ops : ops.slice(1), deletes: [] };
    }
    case "sort":
      return { writes: optionValues(args, ["-o"], ["--output"]), deletes: [] };
    case "uniq": {
      const ops = operands(args, ["-f", "-s", "-w", "--skip-fields", "--skip-chars", "--check-chars"]);
      return { writes: ops.slice(1, 2), deletes: [] };
    }
    case "rm":
    case "rmdir":
    case "unlink":
    case "shred":
    case "srm":
    case "trash":
      return { writes: [], deletes: operands(args) };
    case "find": {
      if (!args.includes("-delete")) return none;
      const roots: string[] = [];
      for (const a of args) {
        if (a.startsWith("-") || a === "(" || a === "!") break;
        roots.push(a);
      }
      return { writes: [], deletes: roots.length ? roots : ["."] };
    }
    case "rsync": {
      const ops = operands(args, ["-e", "--rsh", "--exclude", "--include", "--filter", "-f", "--files-from", "--rsync-path", "--chmod", "--chown"]);
      const dest = lastOf(ops);
      const del = args.some((a) => a.startsWith("--delete") || a === "--remove-source-files");
      return { writes: dest, deletes: del ? dest : [] };
    }
    case "curl":
      return { writes: optionValues(args, ["-o"], ["--output"]), deletes: [] };
    case "wget":
      return { writes: [...optionValues(args, ["-O", "-P"], ["--output-document", "--directory-prefix"])], deletes: [] };
    case "crontab":
      // Installing / removing a crontab writes the user's cron table.
      return args.every((a) => a === "-l" || a.startsWith("-u")) ? none : { writes: ["/var/spool/cron/crontabs/user"], deletes: [] };
    default:
      return none;
  }
}

/**
 * True if every flag spec is present among argv's options (before `--`). A spec is a
 * `|`-separated list of alternatives: `"-r|-R|--recursive"`. Short flags also match
 * inside bundles (`-rfv` has `-r` and `-f`); long flags also match `--flag=value`.
 */
export function hasFlags(argv: string[], specs: string[]): boolean {
  const opts: string[] = [];
  for (const a of argv.slice(1)) {
    if (a === "--") break;
    if (a.startsWith("-") && a !== "-") opts.push(a);
  }
  const present = (flag: string) =>
    flag.startsWith("--")
      ? opts.some((o) => o === flag || o.startsWith(`${flag}=`))
      : flag.length === 2 && opts.some((o) => !o.startsWith("--") && o.slice(1).includes(flag[1]!));
  return specs.every((spec) => spec.split("|").some((alt) => present(alt.trim())));
}
