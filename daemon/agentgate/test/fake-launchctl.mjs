#!/usr/bin/env node
// Test double for /bin/launchctl: `bootstrap` really starts the plist's ProgramArguments in
// the background (so `agentgate setup` can be tested end to end); `bootout` kills it.
// State lives in $FAKE_LAUNCHD_DIR. Never touches the real launchd.
import { spawn } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dir = process.env.FAKE_LAUNCHD_DIR;
mkdirSync(dir, { recursive: true });
const [cmd, ...args] = process.argv.slice(2);
appendFileSync(join(dir, "calls.log"), `${[cmd, ...args].join(" ")}\n`);
const pidFile = join(dir, "pid");
const alive = () => {
  if (!existsSync(pidFile)) return false;
  try {
    process.kill(Number(readFileSync(pidFile, "utf8")), 0);
    return true;
  } catch {
    return false;
  }
};
const unesc = (s) => s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
switch (cmd) {
  case "print":
    process.exit(alive() ? 0 : 113);
  case "bootstrap": {
    if (alive()) {
      console.error("service already loaded");
      process.exit(5);
    }
    const plist = readFileSync(args[1], "utf8");
    const arr = plist.match(/<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/)[1];
    const argv = [...arr.matchAll(/<string>([\s\S]*?)<\/string>/g)].map((m) => unesc(m[1]));
    const envBlock = plist.match(/<key>EnvironmentVariables<\/key>\s*<dict>([\s\S]*?)<\/dict>/)[1];
    const env = { HOME: process.env.HOME };
    for (const m of envBlock.matchAll(/<key>([^<]+)<\/key><string>([\s\S]*?)<\/string>/g)) env[m[1]] = unesc(m[2]);
    Object.assign(env, JSON.parse(process.env.FAKE_LAUNCHD_EXTRA_ENV || "{}"));
    const logFile = unesc(plist.match(/<key>StandardOutPath<\/key><string>([\s\S]*?)<\/string>/)[1]);
    const fd = openSync(logFile, "a");
    const child = spawn(argv[0], argv.slice(1), { env, detached: true, stdio: ["ignore", fd, fd] });
    writeFileSync(pidFile, String(child.pid));
    child.unref();
    process.exit(0);
  }
  case "bootout":
  case "kickstart": {
    if (alive()) {
      try {
        process.kill(Number(readFileSync(pidFile, "utf8")), "SIGTERM");
      } catch {}
    }
    rmSync(pidFile, { force: true });
    process.exit(cmd === "bootout" ? 0 : 1);
  }
  default:
    process.exit(0);
}
