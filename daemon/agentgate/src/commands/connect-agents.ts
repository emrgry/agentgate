import { closeSync, existsSync, openSync, readFileSync, readSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";
import { EXIT } from "../exit-codes.ts";
import { c, log, out } from "../output.ts";
import { installCommand } from "./install.ts";
import { installCodexCommand } from "./install-codex.ts";
import { installCursorCommand } from "./install-cursor.ts";

/**
 * The last step of `agentgate setup`: find the agents on this Mac (Claude Code, Codex, Cursor)
 * and offer to gate them, so a fresh install is one command + one QR scan.
 *
 * Asks on the controlling terminal (/dev/tty): under `curl … | sh` stdin is the script itself.
 * Never asks when stdout is not a terminal (CI, tests, piped output) — it only prints the
 * commands then. `--connect all|none` / AGENTGATE_CONNECT skips the questions.
 */

export type AgentId = "claude-code" | "codex" | "cursor";
export type ConnectMode = "ask" | "all" | "none";

export interface DetectedAgent {
  id: AgentId;
  name: string;
  /** AgentGate's user-level hook is already in that agent's config. */
  connected: boolean;
}

export interface DetectDeps {
  home: string;
  path: string;
  exists(p: string): boolean;
  read(p: string): string | null;
}

const defaultDeps = (): DetectDeps => ({
  home: homedir(),
  path: process.env.PATH ?? "",
  exists: existsSync,
  read: (p) => {
    try {
      return readFileSync(p, "utf8");
    } catch {
      return null;
    }
  },
});

function onPath(bin: string, d: DetectDeps): boolean {
  // launchd/installer PATHs are minimal: also look where these CLIs usually live.
  const dirs = [...d.path.split(delimiter), join(d.home, ".local", "bin"), "/opt/homebrew/bin", "/usr/local/bin"];
  return dirs.some((dir) => dir && d.exists(join(dir, bin)));
}

const mentions = (file: string, marker: string, d: DetectDeps) => (d.read(file) ?? "").includes(marker);

export function detectAgents(d: DetectDeps = defaultDeps()): DetectedAgent[] {
  const found: DetectedAgent[] = [];
  if (onPath("claude", d) || d.exists(join(d.home, ".claude"))) {
    found.push({ id: "claude-code", name: "Claude Code", connected: mentions(join(d.home, ".claude", "settings.json"), "--agentgate-install=claude-code", d) });
  }
  if (onPath("codex", d)) {
    found.push({ id: "codex", name: "Codex", connected: mentions(join(d.home, ".codex", "hooks.json"), "--agentgate-install=codex", d) });
  }
  if (["/Applications/Cursor.app", join(d.home, "Applications", "Cursor.app")].some(d.exists) || d.exists(join(d.home, ".cursor"))) {
    found.push({ id: "cursor", name: "Cursor", connected: mentions(join(d.home, ".cursor", "hooks.json"), "--agentgate-install=cursor", d) });
  }
  return found;
}

export const connectCommandFor = (id: AgentId) => `agentgate install ${id} --user --yes`;

export function parseConnectMode(v: string | undefined): ConnectMode | null {
  if (v === undefined || v === "") return "ask";
  return v === "ask" || v === "all" || v === "none" ? v : null;
}

/** y/yes/empty → yes (default Yes); n/no → no; anything else → ask again (null). */
export function parseAnswer(line: string): boolean | null {
  const a = line.trim().toLowerCase();
  if (a === "" || a === "y" || a === "yes" || a === "e" || a === "evet") return true;
  if (a === "n" || a === "no" || a === "h" || a === "hayır" || a === "hayir") return false;
  return null;
}

/** A tiny synchronous prompt on /dev/tty. null → no terminal to ask on. */
function openTty(): { ask(q: string): string | null; close(): void } | null {
  if (!process.stdout.isTTY) return null;
  let fd: number;
  try {
    fd = openSync("/dev/tty", "r+");
  } catch {
    return null;
  }
  return {
    ask(q: string) {
      writeSync(fd, q);
      const buf = Buffer.alloc(1);
      let line = "";
      for (;;) {
        let n = 0;
        try {
          n = readSync(fd, buf, 0, 1, null);
        } catch {
          return null;
        }
        if (n === 0) return line || null;
        const ch = buf.toString("utf8", 0, n);
        if (ch === "\n") return line;
        line += ch;
      }
    },
    close: () => closeSync(fd),
  };
}

const INSTALLERS: Record<AgentId, () => Promise<number>> = {
  "claude-code": () => installCommand({ agent: "claude-code", user: true, yes: true }),
  codex: () => installCodexCommand({ user: true, yes: true }),
  cursor: () => installCursorCommand({ user: true, yes: true }),
};

export async function connectAgentsStep(mode: ConnectMode, detected: DetectedAgent[] = detectAgents()): Promise<number> {
  const todo = detected.filter((a) => !a.connected);
  for (const a of detected.filter((x) => x.connected)) log.ok(`${a.name} is already gated by AgentGate`);
  if (todo.length === 0) {
    if (detected.length === 0) {
      out(`${c.dim("No Claude Code, Codex or Cursor found. Later:")} agentgate install claude-code|codex|cursor --user --yes`);
    }
    return EXIT.OK;
  }

  const tty = mode === "ask" ? openTty() : null;
  if (mode === "none" || (mode === "ask" && !tty)) {
    out("Gate your agents with:");
    for (const a of todo) out(`  ${connectCommandFor(a.id)}`);
    return EXIT.OK;
  }

  out("");
  out(c.bold("Connect your agents"));
  out(c.dim("Risky actions (git push, deleting files, secrets, deploys…) will wait for your phone."));
  let failed = false;
  try {
    for (const a of todo) {
      let yes = true;
      if (tty) {
        let ans: boolean | null = null;
        while (ans === null) {
          const line = tty.ask(`  Connect ${a.name}? [Y/n] `);
          if (line === null) {
            ans = false;
            break;
          }
          ans = parseAnswer(line);
        }
        yes = ans;
      }
      if (!yes) {
        out(c.dim(`  skipped — later: ${connectCommandFor(a.id)}`));
        continue;
      }
      const code = await INSTALLERS[a.id]();
      if (code !== EXIT.OK) {
        failed = true;
        log.fail(`could not connect ${a.name} — try: ${connectCommandFor(a.id)}`);
      }
    }
  } finally {
    tty?.close();
  }
  // A failed integration must not hide the pairing QR: report it, keep going.
  return failed ? EXIT.ERROR : EXIT.OK;
}
