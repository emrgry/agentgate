import { hostname } from "node:os";
import { ActionDraft } from "@agentgate/protocol";

export interface DraftInput {
  sessionId: string;
  agentType: string;
  agentVersion?: string;
  command: string;
  cwd: string;
  environment?: string;
  repo?: string;
  branch?: string;
}

/**
 * Shell action draft for `agentgate request`. Validated with the protocol schema
 * (throws on invalid input, e.g. over-long command → caller blocks).
 *
 * Only session, agent type, category/operation/tool, command, cwd and resource enter
 * the action hash; repo/branch/hostname are informational context.
 */
export function buildShellDraft(i: DraftInput): ActionDraft {
  const resource: ActionDraft["resource"] = {};
  if (i.environment) resource.environment = i.environment;
  const context: ActionDraft["context"] = { hostname: hostname() };
  if (i.repo) context.repo = i.repo;
  if (i.branch) context.branch = i.branch;
  return ActionDraft.parse({
    session_id: i.sessionId,
    agent: i.agentVersion ? { type: i.agentType, version: i.agentVersion } : { type: i.agentType },
    action: { category: "shell", operation: "execute", tool: "agentgate", command: i.command, cwd: i.cwd },
    resource,
    context,
  });
}

const SAFE_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/;

/** POSIX single-quote escaping. */
export function shellQuote(word: string): string {
  if (word !== "" && SAFE_WORD.test(word)) return word;
  return `'${word.replace(/'/g, `'\\''`)}'`;
}

/**
 * argv after `--` → the command string that is hashed, shown to the human, and passed
 * verbatim to `/bin/sh -c`.
 *  - one argument: taken as a shell command line as-is (`agentgate request -- "a && b"`)
 *  - several: each word is shell-quoted so the command means exactly what the argv
 *    meant (`agentgate request -- echo "a b"` → `echo 'a b'`)
 */
export function commandFromArgv(argv: string[]): string {
  if (argv.length === 1) return argv[0]!;
  return argv.map(shellQuote).join(" ");
}
