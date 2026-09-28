#!/usr/bin/env node
// Tiny zero-dependency stdio MCP server for the AgentGate MCP gateway demo.
// Newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP stdio transport).
// Every tool call appends a line to $MCP_DEMO_LOG (default ./mcp-demo.log) so side effects
// are provable: if a call was blocked by AgentGate, it never shows up in the log.
import { appendFileSync } from "node:fs";
import { resolve } from "node:path";

const LOG = resolve(process.env.MCP_DEMO_LOG || "mcp-demo.log");
const PROTOCOL = "2025-06-18";

const TOOLS = [
  {
    name: "list_inbox",
    title: "List inbox",
    description: "List the latest emails in the inbox.",
    inputSchema: { type: "object", properties: {} },
    annotations: { title: "List inbox", readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "send_email",
    title: "Send email",
    description: "Send an email on the user's behalf.",
    inputSchema: {
      type: "object",
      properties: { to: { type: "string" }, subject: { type: "string" }, body: { type: "string" } },
      required: ["to", "subject", "body"],
    },
    annotations: { title: "Send email", readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  },
  {
    name: "delete_all_emails",
    title: "Delete all emails",
    description: "Permanently delete every email in the mailbox.",
    inputSchema: { type: "object", properties: {} },
    annotations: { title: "Delete all emails", readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "transfer_funds",
    title: "Transfer funds",
    description: "Transfer money to another account.",
    inputSchema: {
      type: "object",
      properties: { amount: { type: "number" }, to: { type: "string" } },
      required: ["amount", "to"],
    },
    annotations: { title: "Transfer funds", readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  },
];

function send(msg) {
  process.stdout.write(`${JSON.stringify(msg)}\n`);
}

function sideEffect(tool, args) {
  appendFileSync(LOG, `${new Date().toISOString()} ${tool} ${JSON.stringify(args ?? {})}\n`);
}

function call(name, args) {
  switch (name) {
    case "list_inbox":
      sideEffect(name, args);
      return { content: [{ type: "text", text: "1. Welcome to AgentGate (from: team@agentgate.dev)\n2. Invoice #42 (from: billing@example.com)" }] };
    case "send_email":
      sideEffect(name, args);
      return { content: [{ type: "text", text: `Email sent to ${args?.to} (subject: ${args?.subject}).` }] };
    case "delete_all_emails":
      sideEffect(name, args);
      return { content: [{ type: "text", text: "Deleted 1,284 emails." }] };
    case "transfer_funds":
      sideEffect(name, args);
      return { content: [{ type: "text", text: `Transferred ${args?.amount} to ${args?.to}.` }] };
    case "fail":
      return { isError: true, content: [{ type: "text", text: "tool failed on purpose" }] };
    default:
      return null;
  }
}

function handle(msg) {
  const { id, method, params } = msg;
  if (method === undefined) return; // responses to our (non-existent) requests
  if (id === undefined) {
    if (method === "demo/crash") process.exit(3);
    return; // notifications (initialized, cancelled, …)
  }
  switch (method) {
    case "initialize":
      return send({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: params?.protocolVersion ?? PROTOCOL,
          capabilities: { tools: { listChanged: true }, resources: {} },
          serverInfo: { name: "agentgate-mcp-demo", version: "0.1.0" },
        },
      });
    case "ping":
      return send({ jsonrpc: "2.0", id, result: {} });
    case "tools/list":
      return send({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
    case "resources/list":
      return send({ jsonrpc: "2.0", id, result: { resources: [{ uri: "demo://inbox", name: "inbox", mimeType: "text/plain" }] } });
    case "tools/call": {
      const delay = Number(params?.arguments?.__delay_ms ?? 0);
      const reply = () => {
        const result = call(params?.name, params?.arguments);
        if (!result) return send({ jsonrpc: "2.0", id, error: { code: -32602, message: `unknown tool: ${params?.name}` } });
        send({ jsonrpc: "2.0", id, result });
      };
      return delay > 0 ? setTimeout(reply, delay) : reply();
    }
    case "demo/ask_client":
      // Server → client request (like sampling/elicitation), to prove both directions relay.
      send({ jsonrpc: "2.0", id: "srv-1", method: "sampling/createMessage", params: { messages: [], maxTokens: 1 } });
      return send({ jsonrpc: "2.0", id, result: { asked: true } });
    case "demo/crash":
      process.exit(3);
      return;
    default:
      return send({ jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } });
  }
}

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    try {
      handle(JSON.parse(line));
    } catch {
      send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
    }
  }
});
process.stdin.on("end", () => process.exit(0));
