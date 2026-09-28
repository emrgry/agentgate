#!/usr/bin/env node
// Fake `codex` for supervisor tests: speaks `codex exec --json` JSONL.
// `--version` prints FAKE_CODEX_VERSION (default 0.50.0; "none" → exit 1).
// The instruction (stdin) is a ';'-separated script:
//   say:<text>      agent_message
//   tool:<cmd>      the AgentGate hook "fires" (invoked + allow receipts), then the command runs
//   nohook:<cmd>    the command runs WITHOUT any receipt (hooks not firing)
//   denied:<cmd>    the hook denies, but the command runs anyway (a bypass)
//   declined:<cmd>  the hook denies and codex declines the command (correct behaviour)
//   patch:<path>    hook fires for apply_patch, then a file_change item
//   sleep:<ms>  fail  args (echo argv as the agent message)
import { appendFileSync } from "node:fs";
import { randomUUID } from "node:crypto";

const args = process.argv.slice(2);
if (args[0] === "--version") {
  const v = process.env.FAKE_CODEX_VERSION ?? "0.50.0";
  if (v === "none") process.exit(1);
  process.stdout.write(`codex-cli ${v}\n`);
  process.exit(0);
}
if (process.env.FAKE_AGENT_LOG) appendFileSync(process.env.FAKE_AGENT_LOG, JSON.stringify({ args, env: { CODEX_HOME: process.env.CODEX_HOME, AGENTGATE_CONTROL_SESSION: process.env.AGENTGATE_CONTROL_SESSION } }) + "\n");
const resuming = args[1] === "resume";
const tid = resuming ? args[args.length - 2] : randomUUID();
const out = (o) => process.stdout.write(JSON.stringify(o) + "\n");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const receipts = process.env.AGENTGATE_GATE_RECEIPTS;
const receipt = (phase, kind, text, paths, decision) =>
  receipts && appendFileSync(receipts, JSON.stringify({ phase, ts: new Date().toISOString(), provider: "codex", kind, text, paths, tool_use_id: null, ...(decision ? { decision } : {}) }) + "\n");
process.on("SIGINT", () => process.exit(130));

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => (input += d));
process.stdin.on("end", async () => {
  out({ type: "thread.started", thread_id: tid });
  out({ type: "turn.started" });
  let n = 0;
  let failed = false;
  for (const step of input.split(";").map((s) => s.trim()).filter(Boolean)) {
    const [cmd, ...rest] = step.split(":");
    const arg = rest.join(":");
    const id = `item_${n++}`;
    const shell = async (status, hook) => {
      if (hook) {
        receipt("invoked", "shell", `bash -lc '${arg}'`, []);
        receipt("decision", "shell", `bash -lc '${arg}'`, [], hook);
      }
      if (status === "declined") {
        out({ type: "item.completed", item: { id, type: "command_execution", command: `bash -lc '${arg}'`, aggregated_output: "", exit_code: null, status: "declined" } });
        return;
      }
      out({ type: "item.started", item: { id, type: "command_execution", command: `bash -lc '${arg}'`, status: "in_progress" } });
      await sleep(20);
      out({ type: "item.completed", item: { id, type: "command_execution", command: `bash -lc '${arg}'`, aggregated_output: "ok\n", exit_code: 0, status } });
    };
    if (cmd === "say") out({ type: "item.completed", item: { id, type: "agent_message", text: arg } });
    else if (cmd === "args") out({ type: "item.completed", item: { id, type: "agent_message", text: JSON.stringify(args) } });
    else if (cmd === "tool") await shell("completed", "allow");
    else if (cmd === "nohook") await shell("completed", null);
    else if (cmd === "denied") await shell("completed", "deny");
    else if (cmd === "declined") await shell("declined", "deny");
    else if (cmd === "patch") {
      receipt("invoked", "file", "", [arg]);
      receipt("decision", "file", "", [arg], "allow");
      out({ type: "item.started", item: { id, type: "file_change", changes: [{ path: `${process.cwd()}/${arg}`, kind: "add" }], status: "in_progress" } });
      out({ type: "item.completed", item: { id, type: "file_change", changes: [{ path: `${process.cwd()}/${arg}`, kind: "add" }], status: "completed" } });
    } else if (cmd === "sleep") await sleep(Number(arg));
    else if (cmd === "fail") failed = true;
  }
  if (failed) {
    out({ type: "turn.failed", error: { message: "model error" } });
    process.exit(1);
  }
  out({ type: "turn.completed", usage: { input_tokens: 10, cached_input_tokens: 0, output_tokens: 5 } });
  process.exit(0);
});
