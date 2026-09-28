import type { ActionSpec, Resource, Risk, RiskLevel } from "@agentgate/protocol";
import { parseSegment, type ParsedSegment } from "./shell.ts";
import { isDynamicPath, isInsideProject, normalizePath, structuredPaths, type PathContext } from "./paths.ts";
import { assessMcp, isMcpInvoke } from "./mcp.ts";

/** MCP client configs: rewriting them reroutes MCP servers around the gateway. */
const MCP_CONFIG_RES: RegExp[] = [
  /(^|\/)Library\/Application Support\/Claude\/claude_desktop_config\.json$/,
  /(^|\/)\.cursor\/mcp\.json$/,
  /(^|\/)\.mcp\.json$/,
  /(^|\/)\.codex\/config\.toml$/,
  /(^|\/)\.claude\.json$/,
];

export const RISK_ORDER: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function maxRisk(a: Risk, b: Risk): Risk {
  return RISK_ORDER[b.level] > RISK_ORDER[a.level] ? b : a;
}

const PROD_RE = /(^|[^a-z])(prod|production|prd|live)([^a-z]|$)/i;

/** Drop commit/tag messages so "fix prod bug" in a message does not mean "production". */
function withoutCommitMessages(command: string): string {
  return command.replace(/(^|\s)(-[a-zA-Z]*m|--message)(=|\s+)("(\\.|[^"\\])*"|'[^']*'|\S+)/g, "$1");
}

/** Best-effort environment inference when the adapter did not supply one. */
export function inferEnvironment(action: ActionSpec, resource: Resource | undefined): string | undefined {
  if (resource?.environment) return resource.environment;
  const haystack = [withoutCommitMessages(action.command ?? ""), JSON.stringify(action.arguments ?? {})].join(" ");
  return PROD_RE.test(haystack) ? "production" : undefined;
}


/** Classification of one shell segment. */
export interface SegmentAssessment {
  risk: Risk;
  /**
   * True when the command matched a known-safe shape (the allowlist). Unrecognized
   * commands fall back to `defaults.unrecognized` (ask) unless a rule decides.
   */
  recognized: boolean;
  /** Normalized paths the command writes / removes (for `writes_to` rules). */
  writes: string[];
  deletes: string[];
}

/** Classify a single (already split) shell segment: the command itself and what it writes. */
export function classifyShellSegment(segment: string, environment: string | undefined, ctx: PathContext = {}): Risk {
  return assessShellSegment(segment, environment, ctx).risk;
}

export function assessShellSegment(segment: string, environment: string | undefined, ctx: PathContext = {}): SegmentAssessment {
  const parsed = parseSegment(segment);
  const base = classifyCommand(parsed, withoutCommitMessages(segment), environment);
  const writes = parsed.writes.filter((w) => w !== "-").map((w) => normalizePath(w, ctx));
  const deletes = parsed.deletes.filter((w) => w !== "-").map((w) => normalizePath(w, ctx));
  let risk: Risk = { level: base.level, reason: base.reason };
  const w = classifyTargets(writes, ctx, "writes");
  if (w) risk = maxRisk(risk, w);
  const d = classifyTargets(deletes, ctx, "removes");
  if (d) risk = maxRisk(risk, d);
  // A symlink inside the project that points at a sensitive / outside path would let a
  // later "in-project" write land there (`ln -s ~/.ssh keys; echo k > keys/authorized_keys`).
  if (parsed.argv[0] === "ln") {
    const ops = parsed.argv.slice(1).filter((a) => !a.startsWith("-"));
    const sources = (ops.length >= 2 ? ops.slice(0, -1) : ops).map((x) => normalizePath(x, ctx));
    const l = classifyTargets(sources, ctx, "links to");
    if (l && RISK_ORDER[l.level] >= RISK_ORDER.high) risk = maxRisk(risk, l);
  }
  return { risk, recognized: base.known, writes, deletes };
}

/** /dev nodes that are safe to write to (no persistent effect). */
const HARMLESS_DEV_RE = /^\/dev\/(null|zero|full|random|urandom|stdout|stderr|stdin|tty|fd\/\d+)$/;
/** Raw block devices / memory: writing destroys data. */
const DEVICE_RE = /^\/dev\/(sd|hd|vd|xvd|nvme|disk|rdisk|mmcblk|md\d|dm-|loop|mapper\/|mem$|kmem$|port$)/;
/** Paths whose modification grants persistence, credentials or code execution. */
const SENSITIVE_PATH_RES: RegExp[] = [
  /(^|\/)\.ssh(\/|$)/,
  /(^|\/)authorized_keys2?$/,
  /(^|\/)\.env(rc|\.[^/]*)?$/,
  /(^|\/)\.(bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin|zlogout|kshrc|cshrc|tcshrc|login|inputrc)$/,
  /(^|\/)\.config\/fish(\/|$)/,
  /^(\/private)?\/etc(\/|$)/,
  /(^|\/)\.git(\/|$)/,
  /(^|\/)\.claude(\/|$)/,
  /(^|\/)\.agentgate(\/|$)/,
  /\.(pem|key|p12|pfx)$/,
  /(^|\/)id_[^/]*$/,
  /(^|\/)(crontab|cron\.(d|daily|hourly|weekly|monthly))(\/|$)/,
  /^\/var\/(spool\/cron|at\/tabs)/,
  /^\/usr\/lib\/cron/,
  /(^|\/)Library\/Launch(Agents|Daemons)(\/|$)/,
  /(^|\/)\.(aws|kube|gnupg|docker)(\/|$)/,
  /(^|\/)\.(npmrc|netrc|pypirc|gitconfig|git-credentials|pgpass)$/,
  /(^|\/)sudoers(\.d)?(\/|$)/,
  /^\/(usr|bin|sbin|boot|lib|lib64|System|Library)(\/|$)/,
];

export function isSensitivePath(path: string): boolean {
  return SENSITIVE_PATH_RES.some((re) => re.test(path));
}

/**
 * Risk contributed by the files a command writes or removes (normalized paths), or null
 * if none matter. Inside the project: medium. Outside the project (except temp dirs),
 * dynamic or sensitive: high. Raw devices: critical.
 */
export function classifyTargets(targets: string[], ctx: PathContext = {}, verb = "writes"): Risk | null {
  let out: Risk | null = null;
  for (const t of targets) {
    let r: Risk | null;
    if (HARMLESS_DEV_RE.test(t)) r = null;
    else if (DEVICE_RE.test(t)) r = { level: "critical", reason: `${verb} raw device ${t}` };
    else if (/^\/dev\/(tcp|udp)\//.test(t)) r = { level: "high", reason: `sends data over the network via ${t}` };
    else if (MCP_CONFIG_RES.some((re) => re.test(t))) r = { level: "critical", reason: `${verb} MCP client config ${t} (reroutes MCP servers)` };
    else if (isDynamicPath(t)) r = { level: "high", reason: `${verb} a path only known at runtime (${t})` };
    else if (isSensitivePath(t)) r = { level: "high", reason: `${verb} sensitive path ${t}` };
    else if (!isInsideProject(t, ctx)) r = { level: "high", reason: `${verb} ${t} outside the project` };
    else r = { level: "medium", reason: `${verb} ${t}` };
    if (r) out = out ? maxRisk(out, r) : r;
  }
  return out;
}

/** Back-compat alias: risk of written paths (normalized without a cwd). */
export function classifyWrites(targets: string[], ctx: PathContext = {}): Risk | null {
  return classifyTargets(targets.map((t) => normalizePath(t, ctx)), ctx, "writes");
}

type Classified = Risk & { known: boolean };
const known = (level: Risk["level"], reason: string): Classified => ({ level, reason, known: true });
const unknown = (level: Risk["level"], reason: string): Classified => ({ level, reason, known: false });

/** Read-only tools (with the guards in classifyCommand). */
const READ_ONLY_BINS = new Set([
  "ls", "cat", "head", "tail", "pwd", "echo", "printf", "wc", "grep", "egrep", "fgrep", "rg", "find", "which",
  "whoami", "id", "date", "env", "printenv", "tree", "stat", "file", "diff", "cmp", "comm", "true", "false",
  "test", "[", "basename", "dirname", "realpath", "readlink", "du", "df", "uname", "cut", "tr", "nl",
  "column", "jq", "md5", "md5sum", "shasum", "sha1sum", "sha256sum", "sort", "uniq", "type", "cd",
  "pushd", "popd", "sleep", "wait", "exit", ":", "set", "unset", "export", "declare", "local", "hostname",
  "sed", "awk", "gawk", "mawk", "nawk", "xxd", "hexdump", "od", "strings", "command", "tsc",
]);
const INFO_ARGS = new Set(["--version", "-V", "--help", "version", "help"]);
const RUNS_PROJECT_CODE_RE =
  /^(python[0-9.]*|node|nodejs|perl|ruby|php|lua|deno|bun|tsx|ts-node|osascript|(ba|z|da|k|c|tc|mk|a|fi)?sh|fish|make|gmake|just|rake|task|gradle|gradlew|mvn|npx|bunx|pnpx)$/;
const DB_CLIENTS = new Set(["psql", "mysql", "mariadb", "sqlite3", "mongosh", "mongo", "redis-cli", "clickhouse-client", "sqlcmd", "duckdb"]);
const TEXT_BINS = new Set(["echo", "printf", "grep", "egrep", "fgrep", "rg", "cat", "git"]);
const NETWORK_BINS = new Set(["ssh", "scp", "sftp", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "rsync"]);
const LOCALHOST_URL_RE = /^(https?:\/\/)?(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(:\d+)?(\/|$)/i;

/** The command's own risk and whether it is a known-safe (allowlisted) shape. */
function classifyCommand(p: ParsedSegment, segment: string, environment: string | undefined): Classified {
  const argv = p.argv;
  const bin = argv[0] ?? "";
  const sub = argv[1] ?? "";
  const rest = argv.slice(1);
  const head3 = argv.slice(1, 4).join(" ");
  const prod = environment === "production" || PROD_RE.test(segment);
  const hasFlag = (...flags: string[]) => rest.some((a) => flags.includes(a) || flags.some((f) => f.startsWith("--") && a.startsWith(`${f}=`)));
  const shortFlags = rest.filter((a) => /^-[a-zA-Z]+$/.test(a)).map((a) => a.slice(1)).join("");
  const hasShortFlag = (letter: string) => shortFlags.includes(letter);
  const ops = rest.filter((a) => !a.startsWith("-"));

  if (argv.length === 0) return known("low", "variable assignment / no-op");

  // ── critical ──
  if (bin === "rm" && (hasShortFlag("r") || hasShortFlag("R") || hasFlag("--recursive")) && (hasShortFlag("f") || hasFlag("--force"))) {
    return known("critical", "recursive forced deletion");
  }
  if (bin === "git" && sub === "push" && (hasFlag("--force", "--force-with-lease", "--mirror", "--delete", "--prune") || hasShortFlag("f") || hasShortFlag("d") || rest.some((a) => a.startsWith("+") || a.startsWith(":")))) {
    return known("critical", "force push / remote ref deletion rewrites shared history");
  }
  if (!TEXT_BINS.has(bin) && (/\bdrop\s+(database|schema|table)\b/i.test(segment) || /\btruncate\s+table\b/i.test(segment))) {
    return known("critical", "database drop/truncate");
  }
  if (["mkfs", "dd", "shred", "wipefs", "fdisk", "diskutil"].includes(bin) || bin.startsWith("mkfs.")) {
    if (bin === "diskutil" && ["list", "info"].includes(sub)) return known("low", "disk info");
    return known("critical", "raw disk / irreversible data destruction");
  }
  if (bin === "kubectl" && ["delete", "drain"].includes(sub) && prod) return known("critical", "destructive production Kubernetes operation");
  if (bin === "terraform" && sub === "destroy") return known("critical", "infrastructure destruction");
  if (!TEXT_BINS.has(bin) && /\b(secret|secrets)\b/.test(head3) && /\b(set|put|create|delete|rm|update|edit|remove)\b/.test(head3)) {
    return known("critical", "secret modification");
  }
  if (bin === "gh" && ["repo", "release", "gist", "ssh-key", "gpg-key", "variable", "label", "run", "cache"].includes(sub) && ["delete", "archive", "rename", "edit"].includes(argv[2] ?? "")) {
    return known(sub === "repo" && argv[2] === "delete" ? "critical" : "high", `gh ${sub} ${argv[2]} changes a remote resource`);
  }
  if (bin === "aws" && rest.some((a) => ["rm", "rb"].includes(a) || /^(delete|terminate|remove|destroy|deregister|purge)/.test(a))) {
    return known("critical", "destructive AWS operation");
  }
  if (["gcloud", "az", "doctl", "heroku", "fly", "flyctl", "vercel", "netlify"].includes(bin) && rest.some((a) => /^(delete|destroy|remove|rm|purge)$/.test(a))) {
    return known("critical", `destructive ${bin} operation`);
  }
  if ((bin === "docker" || bin === "podman") && rest.includes("prune") && (hasShortFlag("a") || hasFlag("--all", "--volumes"))) {
    return known("critical", "prunes all containers / images / volumes");
  }

  // ── high ──
  if (bin === "git") {
    const g = classifyGit(argv, hasFlag, hasShortFlag, ops);
    if (g) return prod && RISK_ORDER[g.level] < RISK_ORDER.high ? known("high", "production command") : g;
  }
  if (["rm", "rmdir", "unlink", "srm", "trash"].includes(bin)) return known("high", "file deletion");
  if (bin === "find" && hasFlag("-delete")) return known("high", "file deletion");
  if (bin === "kubectl" && ["apply", "delete", "scale", "rollout", "patch", "edit", "replace", "drain", "cordon", "create", "set", "annotate", "label", "exec", "cp"].includes(sub)) {
    return known("high", "Kubernetes mutation");
  }
  if (["terraform", "pulumi", "cdk", "serverless", "sls"].includes(bin) && ["apply", "up", "deploy", "import"].includes(sub)) return known("high", "infrastructure change");
  if (bin !== "git" && [bin, sub, argv[2] ?? ""].some((t) => /(^|[-_./:])(deploy|release|publish)([-_./:]|$)/.test(t))) {
    return known("high", "deployment / publication");
  }
  if (DB_CLIENTS.has(bin)) {
    if (/\b(insert|update|delete|alter|create|grant|revoke)\b/i.test(segment)) return known("high", "database mutation");
    if (hasFlag("-f", "--file") || hasFlag("--init-command")) return known("high", "runs a SQL file");
  }
  if (bin === "curl" || bin === "wget") {
    const sends = httpSendsData(bin, rest);
    if (sends) return known("high", sends);
  }
  if ((bin === "docker" || bin === "podman") && (rest.includes("prune") || ["rm", "rmi", "kill", "stop"].includes(sub) || (["volume", "image", "container", "network", "system"].includes(sub) && ["rm", "prune"].includes(argv[2] ?? "")))) {
    return known("high", "removes containers / images / volumes");
  }
  if (["docker-compose"].includes(bin) || (bin === "docker" && sub === "compose")) {
    if (rest.includes("down") && (hasShortFlag("v") || hasFlag("--volumes", "--rmi"))) return known("high", "removes compose volumes / images");
  }
  if (["chmod", "chown", "chgrp"].includes(bin) && (hasShortFlag("R") || hasFlag("--recursive") || (bin === "chmod" && worldWritable(ops[0] ?? "")))) {
    return known("high", "broad permission change");
  }
  if (bin === "rg" && rest.some((a) => a === "--pre" || a.startsWith("--pre="))) return known("high", "rg --pre runs a command on every file");
  if (bin === "crontab" && !rest.every((a) => a === "-l" || a.startsWith("-u"))) return known("high", "installs or removes a crontab");
  if (bin === "launchctl" && !["list", "print", "print-disabled", "version", "help"].includes(sub)) return known("high", "changes launchd services");
  if (bin === "systemctl" && !["status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "list-timers", "show", "cat"].includes(sub)) {
    return known("high", "changes system services");
  }
  if (NETWORK_BINS.has(bin)) return known("high", "opens a network connection / transfers files");
  if (bin === "systemctl" || bin === "launchctl") return known("low", "service status query");
  if (prod) return known("high", "production command");

  // ── low: info and read-only (allowlist) ──
  if (rest.length === 1 && INFO_ARGS.has(rest[0]!)) return known("low", "version / help");
  if (READ_ONLY_BINS.has(bin)) {
    const r = classifyReadOnly(bin, rest, ops, hasFlag);
    if (r) return r;
  }

  // ── medium: known local changes (allowlist) ──
  if (["npm", "pnpm", "yarn", "bun"].includes(bin)) {
    if (["install", "i", "ci", "add"].includes(sub) || (bin === "yarn" && rest.length === 0)) {
      return hasFlag("-g", "--global", "--location=global") ? unknown("medium", "global package install") : known("medium", "package install");
    }
    if (["ls", "list", "view", "info", "outdated", "why", "explain", "root", "bin", "prefix", "audit"].includes(sub) && !hasFlag("fix")) {
      return known("low", "package metadata query");
    }
    if (["test", "t", "run", "run-script", "start", "exec", "dlx", "x", "tst"].includes(sub) || bin === "yarn" || bin === "bun") {
      return unknown("medium", "runs project code (package.json script / package binary)");
    }
  }
  if (["pip", "pip3"].includes(bin) && sub === "install") return known("medium", "package install");
  if (["pip", "pip3"].includes(bin) && ["list", "show", "freeze"].includes(sub)) return known("low", "package metadata query");
  if (["mkdir", "touch", "cp", "mv", "ln", "truncate", "tee", "install"].includes(bin)) return known("medium", "local file change");
  if (["chmod", "chown", "chgrp"].includes(bin)) return known("medium", "permission change");

  // ── not on the allowlist ──
  if (bin === "curl" || bin === "wget") {
    const urls = rest.filter((a) => /^(https?:\/\/|[a-z0-9.-]+(:\d+)?\/)/i.test(a) || /^(localhost|127\.0\.0\.1)/.test(a));
    if (urls.length > 0 && urls.every((u) => LOCALHOST_URL_RE.test(u))) return known("medium", "HTTP GET to localhost");
    return unknown("medium", "network request");
  }
  if (RUNS_PROJECT_CODE_RE.test(bin)) return unknown("medium", "runs project code (script / build tool)");
  return unknown("medium", "unrecognized command (not on the allowlist)");
}

/** chmod mode that grants write to "other" (e.g. 777, 666, o+w, a+w, +w). */
function worldWritable(mode: string): boolean {
  if (/^[0-7]{3,4}$/.test(mode)) return [2, 3, 6, 7].includes(Number(mode[mode.length - 1]));
  return mode.split(",").some((clause) => {
    const m = /^([ugoa]*)[+=]([rwxXst]*)$/.exec(clause);
    return !!m && m[2]!.includes("w") && (m[1] === "" || /[oa]/.test(m[1]!));
  });
}

/** git: returns a classification, or null to fall through. */
function classifyGit(
  argv: string[],
  hasFlag: (...f: string[]) => boolean,
  hasShortFlag: (l: string) => boolean,
  ops: string[],
): Classified | null {
  const sub = argv[1] ?? "";
  const rest = argv.slice(2);
  const sops = ops.slice(1); // operands after the subcommand
  if (argv.length === 1) return known("low", "git usage");
  switch (sub) {
    case "push":
      return known("high", "pushes commits to a remote");
    case "rebase":
      return known("high", "rewrites local history");
    case "reset":
      return hasFlag("--hard", "--merge", "--keep") ? known("high", "discards working tree changes") : known("medium", "moves HEAD / unstages");
    case "clean":
      return hasFlag("-n", "--dry-run") || hasShortFlag("n") ? known("low", "git clean dry run") : known("high", "deletes untracked files");
    case "restore":
      return (hasFlag("--staged", "-S") && !hasFlag("--worktree", "-W")) ? known("medium", "unstages changes") : known("high", "discards working tree changes");
    case "checkout": {
      if (hasFlag("-f", "--force", "--", "-p", "--patch", "--ours", "--theirs", "--merge", "-m") || rest.includes(".")) return known("high", "discards working tree changes");
      if (hasFlag("-b", "-B", "--orphan", "-t", "--track")) return known("medium", "creates / switches branch");
      if (sops.length === 1 && !/(^\.|\.[A-Za-z0-9]{1,5}$|^\*|\/\.)/.test(sops[0]!) ) return known("medium", "switches branch");
      if (sops.length === 0) return known("low", "git checkout (no-op)");
      return known("high", "may overwrite files in the working tree");
    }
    case "switch":
      return hasFlag("-f", "--force", "--discard-changes") ? known("high", "discards working tree changes") : known("medium", "switches branch");
    case "branch":
      if (hasFlag("--delete", "--move", "--copy", "--force", "--set-upstream-to", "-u", "--unset-upstream", "--edit-description") || /[dDmMcCf]/.test(rest.filter((a) => /^-[a-zA-Z]+$/.test(a)).join(""))) {
        return known("high", "deletes / renames / rewires branches");
      }
      return sops.length > 0 && !hasFlag("--list", "-l", "--contains", "--merged", "--no-merged", "--points-at") ? known("medium", "creates a branch") : known("low", "lists branches");
    case "tag":
      if (hasFlag("-d", "--delete", "-f", "--force")) return known("high", "deletes / moves tags");
      return sops.length > 0 && !hasFlag("-l", "--list", "--contains", "--points-at") ? known("medium", "creates a tag") : known("low", "lists tags");
    case "remote": {
      const action = sops[0] ?? "";
      if (["add", "remove", "rm", "rename", "set-url", "set-head", "set-branches", "prune", "update"].includes(action)) return known("high", "changes git remotes");
      return known("low", "lists remotes");
    }
    case "config": {
      const reads = hasFlag("--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l", "--show-origin", "--show-scope") || ["get", "list"].includes(sops[0] ?? "");
      const writes = hasFlag("--add", "--unset", "--unset-all", "--replace-all", "--edit", "-e", "--rename-section", "--remove-section") || ["set", "unset", "edit", "rename-section", "remove-section"].includes(sops[0] ?? "");
      if (writes || (!reads && sops.length >= 2)) return known("high", "changes git configuration (hooks, remotes, pagers…)");
      return known("low", "reads git configuration");
    }
    case "stash": {
      const action = sops[0] ?? "push";
      if (["drop", "clear"].includes(action)) return known("high", "discards stashed changes");
      if (["list", "show"].includes(action)) return known("low", "lists stashes");
      return known("medium", "stashes / restores changes");
    }
    case "commit":
      if (hasFlag("--no-verify") || hasShortFlag("n")) return unknown("medium", "commit --no-verify skips hooks");
      return known("medium", "local commit");
    case "add":
    case "pull":
    case "fetch":
    case "merge":
    case "cherry-pick":
    case "revert":
    case "apply":
    case "init":
    case "mv":
      return known("medium", "local git state change");
    case "rm":
      return hasFlag("--cached") ? known("medium", "untracks files") : known("high", "deletes tracked files");
    case "update-ref":
    case "filter-branch":
    case "filter-repo":
    case "replace":
    case "prune":
    case "gc":
      return known("high", "rewrites / prunes repository history");
    case "reflog":
      return ["expire", "delete"].includes(sops[0] ?? "") ? known("high", "destroys reflog entries") : known("low", "reads reflog");
    case "worktree":
      return ["list"].includes(sops[0] ?? "") ? known("low", "lists worktrees") : unknown("medium", "changes worktrees");
    case "diff":
    case "log":
    case "show":
    case "format-patch":
      if (hasFlag("--output", "-o", "--ext-diff", "--textconv") && !hasFlag("--no-ext-diff")) {
        return hasFlag("--output", "-o") ? unknown("medium", "writes git output to a file") : known("low", "read-only git command");
      }
      return sub === "format-patch" ? unknown("medium", "writes patch files") : known("low", "read-only git command");
    case "status":
    case "blame":
    case "rev-parse":
    case "rev-list":
    case "ls-files":
    case "ls-tree":
    case "ls-remote":
    case "cat-file":
    case "describe":
    case "shortlog":
    case "grep":
    case "whatchanged":
    case "name-rev":
    case "merge-base":
    case "check-ignore":
    case "var":
    case "help":
    case "version":
    case "count-objects":
      return known("low", "read-only git command");
    default:
      return null;
  }
}

/** Guards for read-only tools; null means "not the read-only shape". */
function classifyReadOnly(bin: string, rest: string[], ops: string[], hasFlag: (...f: string[]) => boolean): Classified | null {
  switch (bin) {
    case "find":
      if (rest.some((a) => /^-(exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$/.test(a))) return null;
      break;
    case "date":
      if (hasFlag("-s", "--set")) return null;
      break;
    case "hostname":
      if (ops.length > 0) return null;
      break;
    case "sed":
      if (rest.some((a) => (/^-[a-zA-Z]*i/.test(a) && !a.startsWith("--")) || a.startsWith("--in-place"))) {
        return known("medium", "in-place edit");
      }
      if (ops.some((a) => /(^|[;}\s\d$/])[ewW](\s|;|$)/.test(a))) return null;
      break;
    case "awk":
    case "gawk":
    case "mawk":
    case "nawk":
      if (ops.some((a) => /[>|]|\bsystem\s*\(/.test(a))) return null;
      if (hasFlag("-f", "--file") || rest.some((a) => a.startsWith("-f"))) return null;
      break;
    case "sort":
      if (hasFlag("-o", "--output")) return known("medium", "writes sorted output");
      break;
    case "uniq":
      if (ops.length > 1) return known("medium", "writes output file");
      break;
    case "tsc":
      return hasFlag("--noEmit") || hasFlag("--version", "-v") ? known("low", "type check") : known("medium", "TypeScript compiler");
    case "command":
      if (!(rest[0] === "-v" || rest[0] === "-V")) return null;
      break;
    case "rg":
      if (rest.some((a) => a.startsWith("--pre"))) return null;
      break;
    default:
      break;
  }
  return known("low", "read-only command");
}

/** Why a curl/wget invocation sends data, or null for a plain download. */
function httpSendsData(bin: string, args: string[]): string | null {
  if (bin === "curl") {
    for (let i = 0; i < args.length; i++) {
      const a = args[i]!;
      if (/^--(data|data-ascii|data-binary|data-raw|data-urlencode|json|form|form-string|upload-file|post301|post302|post303)(=|$)/.test(a)) {
        return `curl ${a.split("=")[0]} sends data`;
      }
      if (/^--request(=|$)/.test(a)) {
        const m = (a.includes("=") ? a.split("=")[1] : args[i + 1]) ?? "";
        if (!/^(GET|HEAD|OPTIONS)$/i.test(m)) return `curl --request ${m} mutates`;
      }
      if (/^-[a-zA-Z]+/.test(a) && !a.startsWith("--")) {
        const letters = a.slice(1);
        // Short options that take a value end the bundle: -XPOST, -d@file, -Fx=y, -T file.
        for (let k = 0; k < letters.length; k++) {
          const c = letters[k]!;
          if (c === "d" || c === "F" || c === "T") return `curl -${c} sends data`;
          if (c === "X") {
            const m = letters.slice(k + 1) || args[i + 1] || "";
            if (!/^(GET|HEAD|OPTIONS)$/i.test(m)) return `curl -X ${m} mutates`;
            break;
          }
          if ("oHuAeEKrwUxyzCmbc".includes(c)) break; // value-taking option: rest is its value
        }
      }
    }
    return null;
  }
  for (const a of args) {
    if (/^--(post-data|post-file|body-data|body-file)(=|$)/.test(a)) return `wget ${a.split("=")[0]} sends data`;
    if (/^--method(=|$)/.test(a)) {
      const m = a.split("=")[1] ?? "";
      if (!/^(GET|HEAD|OPTIONS)$/i.test(m)) return `wget --method ${m || "(non-GET)"} mutates`;
    }
  }
  return null;
}

/** Risk for non-shell canonical actions, keyed on "category.operation". */
export function classifyStructured(action: ActionSpec, environment: string | undefined, ctx: PathContext = {}): Risk {
  const type = `${action.category}.${action.operation}`;
  const prod = environment === "production";
  const table: Record<string, Risk> = {
    "filesystem.read": { level: "low", reason: "file read" },
    "filesystem.write": { level: "medium", reason: "file edit" },
    "filesystem.delete": { level: "high", reason: "file deletion" },
    "git.push": { level: "high", reason: "pushes commits to a remote" },
    "git.force_push": { level: "critical", reason: "force push" },
    "database.read": { level: "low", reason: "database read" },
    "database.write": { level: "high", reason: "database mutation" },
    "database.drop": { level: "critical", reason: "database drop" },
    "http.request": { level: "medium", reason: "outbound HTTP request" },
    "email.send": { level: "high", reason: "sends email on the user's behalf" },
    "payment.create": { level: "critical", reason: "moves money" },
    "cloud.deploy": { level: "high", reason: "deployment" },
    "secret.read": { level: "high", reason: "secret access" },
    "secret.write": { level: "critical", reason: "secret modification" },
    "mcp.invoke": { level: "medium", reason: "MCP tool invocation" },
  };
  let base: Risk = table[type] ?? { level: "medium" as const, reason: `unclassified ${type}` };
  if (isMcpInvoke(action)) base = assessMcp(action, { ...ctx, cwd: action.cwd ?? ctx.cwd }).risk;
  // File edits/deletes are judged on where they land (outside the project, sensitive, device…).
  if (action.category === "filesystem" && action.operation !== "read") {
    const paths = structuredPaths(action.arguments).map((p) => normalizePath(p, { ...ctx, cwd: action.cwd ?? ctx.cwd }));
    const t = classifyTargets(paths, { ...ctx, cwd: action.cwd ?? ctx.cwd }, action.operation === "delete" ? "removes" : "writes");
    if (t) base = maxRisk(base, t);
  }
  if (prod && RISK_ORDER[base.level] < RISK_ORDER.high) return { level: "high", reason: `${base.reason} in production` };
  return base;
}
