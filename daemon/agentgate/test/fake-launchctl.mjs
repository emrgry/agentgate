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
    writeFileSync(join(dir, "plist-path"), args[1]);
    start(args[1]);
    process.exit(0);
  }
  case "bootout":
  case "kickstart": {
    let old = null;
    if (alive()) {
      old = Number(readFileSync(pidFile, "utf8"));
      try {
        process.kill(old, "SIGTERM");
      } catch {}
    }
    rmSync(pidFile, { force: true });
    if (cmd === "bootout") process.exit(0);
    // `kickstart -k`: restart the loaded job from the plist it was bootstrapped with.
    const saved = join(dir, "plist-path");
    if (!existsSync(saved)) process.exit(113);
    for (let i = 0; old && i < 100; i++) {
      try {
        process.kill(old, 0); // still shutting down (releasing its port)
      } catch {
        break;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    start(readFileSync(saved, "utf8"));
    process.exit(0);
  }
  default:
    process.exit(0);
}

function start(plistFile) {
  {
    const plist = readFileSync(plistFile, "utf8");
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
  }
}
