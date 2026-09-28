#!/usr/bin/env node
// Fake `hermes` for supervisor tests. `chat --help` mentions --format unless FAKE_HERMES_TEXT=1.
// stream-json mode: system/init, text deltas, tool_use/tool_result (hook "fires" unless nohook:), result.
// text mode (-z): prints the final text only.
import { appendFileSync } from "node:fs";

const args = process.argv.slice(2);
if (args.includes("--help")) {
  process.stdout.write(`usage: hermes chat [-q QUERY] [--oneshot] ${process.env.FAKE_HERMES_TEXT === "1" ? "" : "[--format {text,stream-json}]"} [-r ID]\n`);
  process.exit(0);
}
if (process.env.FAKE_AGENT_LOG) appendFileSync(process.env.FAKE_AGENT_LOG, JSON.stringify({ args, home: process.env.HERMES_HOME }) + "\n");
const ri = args.indexOf("-r");
const sid = ri >= 0 ? args[ri + 1] : "20260926_120000_abc";
const out = (o) => process.stdout.write(JSON.stringify({ timestamp: new Date().toISOString(), ...o }) + "\n");
const receipts = process.env.AGENTGATE_GATE_RECEIPTS;
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => (input += d));
process.stdin.on("end", () => {
  const steps = input.split(";").map((s) => s.trim()).filter(Boolean);
  if (!args.includes("stream-json")) {
    process.stdout.write(steps.filter((s) => s.startsWith("say:")).map((s) => s.slice(4)).join("\n") + "\n");
    process.exit(0);
  }
  out({ type: "system", subtype: "init", session_id: sid });
  let text = "";
  for (const step of steps) {
    const [cmd, ...rest] = step.split(":");
    const arg = rest.join(":");
    if (cmd === "say") {
      for (const part of [arg.slice(0, 2), arg.slice(2)]) out({ type: "text", text: part });
      text = arg;
    } else if (cmd === "tool" || cmd === "nohook") {
      if (cmd === "tool" && receipts) {
        appendFileSync(receipts, JSON.stringify({ phase: "invoked", kind: "shell", text: arg, paths: [], tool_use_id: null }) + "\n");
        appendFileSync(receipts, JSON.stringify({ phase: "decision", kind: "shell", text: arg, paths: [], tool_use_id: null, decision: "allow" }) + "\n");
      }
      out({ type: "tool_use", name: "terminal", input: { command: arg } });
      out({ type: "tool_result", name: "terminal", output: "ok", duration_ms: 1, is_error: false });
    }
  }
  out({ type: "result", session_id: sid, exit_code: 0, text, tokens: { input: 3, output: 4 }, duration_ms: 5 });
  process.exit(0);
});
