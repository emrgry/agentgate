#!/usr/bin/env node
// Fake provider binary for supervisor tests: speaks Claude Code stream-json.
// The instruction (stdin) is a ';'-separated script:
//   say:<text>  tool:<cmd>  ask:<question>  sleep:<ms>  ticks:<n>  fail  crash  hang  child
//   write:<path>=<content>   (writes a file in cwd; "\\n" → newline)
//   test:<command>|<exit>|<output>   (a Bash tool call + result with that output; "\\n" → newline)
//   retry   (system/api_retry)   cost:<usd>  (total_cost_usd of the result)   escape (setsid grandchild)
import { spawn } from "node:child_process";
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";

const args = process.argv.slice(2);
// `claude auth status` (JSON) — billing detection. FAKE_AUTH_METHOD=claude.ai → subscription.
if (args[0] === "auth" && args[1] === "status") {
  process.stdout.write(JSON.stringify({ loggedIn: true, authMethod: process.env.FAKE_AUTH_METHOD ?? "api_key" }) + "\n");
  process.exit(0);
}
const ri = args.indexOf("--resume");
const sid = ri >= 0 ? args[ri + 1] : process.env.FAKE_SESSION_ID || randomUUID();
if (process.env.FAKE_AGENT_LOG) appendFileSync(process.env.FAKE_AGENT_LOG, JSON.stringify({ args, pid: process.pid, cwd: process.cwd(), path: process.env.PATH, managed: process.env.AGENTGATE_MANAGED_SESSION }) + "\n");
const out = (o) => process.stdout.write(JSON.stringify({ ...o, session_id: sid }) + "\n");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
process.on("SIGINT", () => process.exit(130));

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => (input += d));
process.stdin.on("end", async () => {
  if (process.env.FAKE_INIT_DELAY_MS) await sleep(Number(process.env.FAKE_INIT_DELAY_MS));
  out({ type: "system", subtype: "init", cwd: process.cwd(), model: "fake", permissionMode: "default" });
  let blocked = false;
  let last = "";
  let cost = 0.01;
  let n = 0;
  // Auto-continuation turns ("[AgentGate] Background command(s) finished …") run FAKE_ON_AGENTGATE.
  if (input.startsWith("[AgentGate]")) {
    if (process.env.FAKE_AGENT_LOG) appendFileSync(process.env.FAKE_AGENT_LOG, JSON.stringify({ auto: input }) + "\n");
    input = process.env.FAKE_ON_AGENTGATE ?? "say:continued";
  }
  for (const step of input.split(";").map((s) => s.trim()).filter(Boolean)) {
    const [cmd, ...rest] = step.split(":");
    const arg = rest.join(":");
    if (cmd === "say") {
      last = arg;
      out({ type: "assistant", message: { role: "assistant", content: [{ type: "text", text: arg }] } });
    } else if (cmd === "tool") {
      out({ type: "assistant", message: { content: [{ type: "tool_use", id: "toolu_1", name: "Bash", input: { command: arg } }] } });
      out({ type: "user", message: { content: [{ type: "tool_result", tool_use_id: "toolu_1", content: "ok", is_error: false }] } });
    } else if (cmd === "ask") {
      last = arg;
      blocked = true;
      out({ type: "assistant", message: { content: [{ type: "text", text: arg }] } });
    } else if (cmd === "sleep") await sleep(Number(arg));
    else if (cmd === "ticks") {
      for (let i = 0; i < Number(arg); i++) {
        out({ type: "assistant", message: { content: [{ type: "text", text: `tick ${i}` }] } });
        last = `tick ${i}`;
        await sleep(100);
      }
    } else if (cmd === "fail") {
      out({ type: "result", subtype: "error_during_execution", is_error: true, num_turns: 0, errors: ["simulated failure"], total_cost_usd: 0, usage: {} });
      process.exit(1);
    } else if (cmd === "write") {
      const [path, ...content] = arg.split("=");
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, content.join("=").replace(/\\n/g, "\n"));
      out({ type: "assistant", message: { content: [{ type: "tool_use", id: `toolu_w${n}`, name: "Write", input: { file_path: path } }] } });
      out({ type: "user", message: { content: [{ type: "tool_result", tool_use_id: `toolu_w${n++}`, content: "ok", is_error: false }] } });
    } else if (cmd === "test") {
      const [command, exit, ...output] = arg.split("|");
      const id = `toolu_t${n++}`;
      out({ type: "assistant", message: { content: [{ type: "tool_use", id, name: "Bash", input: { command } }] } });
      out({ type: "user", message: { content: [{ type: "tool_result", tool_use_id: id, content: output.join("|").replace(/\\n/g, "\n"), is_error: exit !== "0" }] } });
    } else if (cmd === "usage") {
      // Assistant API message with usage (mid-turn cost estimate): usage:<model>:<input>:<output>
      const [model, inp, outp] = arg.split(":");
      out({ type: "assistant", message: { id: `msg_${n++}`, model, role: "assistant", content: [{ type: "text", text: `working ${n}` }], usage: { input_tokens: Number(inp), output_tokens: Number(outp), cache_creation_input_tokens: 0, cache_read_input_tokens: 0 } } });
    } else if (cmd === "retry") {
      out({ type: "system", subtype: "api_retry", attempt: 1, error: "overloaded" });
    } else if (cmd === "cost") {
      cost = Number(arg);
    } else if (cmd === "bg") {
      // Like Claude's run_in_background: a detached child (own session/group) that outlives the turn.
      const c = spawn(process.execPath, ["-e", `setTimeout(()=>{}, ${Number(arg) || 1000})`], { stdio: "ignore", detached: true });
      c.unref();
      if (process.env.FAKE_CHILD_PID) appendFileSync(process.env.FAKE_CHILD_PID, `${c.pid}\n`);
      const id = `toolu_bg${n++}`;
      out({ type: "assistant", message: { content: [{ type: "tool_use", id, name: "Bash", input: { command: `sleep ${arg}`, run_in_background: true } }] } });
      out({ type: "user", message: { content: [{ type: "tool_result", tool_use_id: id, content: `Command running in background with ID: b${n}. Output is being written to: /private/tmp/claude-501/proj/tasks/b${n}.output`, is_error: false }] } });
      await sleep(400); // stays alive briefly (like Claude), so the supervisor sees the child
    } else if (cmd === "escape") {
      // A grandchild in its own session/process group (escapes the turn's group), still our descendant.
      const c = spawn(process.execPath, ["-e", "setTimeout(()=>{},600000)"], { stdio: "ignore", detached: true }); // detached = setsid
      if (process.env.FAKE_CHILD_PID) writeFileSync(process.env.FAKE_CHILD_PID, String(c.pid));
      await sleep(600_000);
    } else if (cmd === "crash") process.exit(3);
    else if (cmd === "hang") await sleep(600_000);
    else if (cmd === "child") {
      const c = spawn(process.execPath, ["-e", "setTimeout(()=>{},600000)"], { stdio: "ignore" });
      if (process.env.FAKE_CHILD_PID) writeFileSync(process.env.FAKE_CHILD_PID, String(c.pid));
      await sleep(600_000);
    }
  }
  out({ type: "system", subtype: "post_turn_summary", status_category: blocked ? "blocked" : "completed", needs_action: blocked ? last : "" });
  out({ type: "result", subtype: "success", is_error: false, num_turns: 1, result: last, total_cost_usd: cost, duration_ms: 50, usage: { input_tokens: 10, output_tokens: 5 } });
  process.exit(0);
});
