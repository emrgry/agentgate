import { describe, expect, it } from "vitest";
import type { RiskLevel } from "@agentgate/protocol";
import { classifyShellSegment, classifyStructured, inferEnvironment, maxRisk } from "../src/index.ts";

/** Risk levels table from the product spec (plus a few close relatives). */
const TABLE: Array<[RiskLevel, string]> = [
  // LOW
  ["low", "git status"],
  ["low", "git diff HEAD~1"],
  ["low", "git log --oneline"],
  ["low", "ls -la"],
  ["low", "cat README.md"],
  ["low", "grep -r foo src"],
  ["low", "find . -name '*.ts'"],
  // MEDIUM
  ["medium", 'git commit -m "fix: typo"'],
  ["medium", "git add ."],
  ["medium", "git checkout -b feature"],
  ["medium", "npm install lodash"],
  ["medium", "npm i"],
  ["medium", "pnpm add zod"],
  ["medium", "pip install requests"],
  ["medium", "brew install jq"],
  ["medium", "make build"],
  ["medium", "git pushx"],
  // MEDIUM: executes project code (package.json scripts, Makefiles, scripts)
  ["medium", "npm test"],
  ["medium", "npm run test:unit"],
  ["medium", "pnpm test"],
  // HIGH
  ["high", "git push origin main"],
  ["high", "git push"],
  ["high", "rm temp.txt"],
  ["high", "rm -r build"],
  ["high", "rmdir build"],
  ["high", "find . -name '*.log' -delete"],
  ["high", "./deploy.sh"],
  ["high", "npm run deploy"],
  ["high", "npm publish"],
  ["high", "vercel deploy --prod"],
  ["high", "kubectl apply -f app.yaml"],
  ["high", "terraform apply"],
  ["high", "git reset --hard HEAD~3"],
  ["high", "git clean -fd"],
  ["high", 'curl -X POST https://api.example.com/x'],
  ["high", "chmod -R 777 ."],
  ["high", "psql -c 'select 1' --host=prod-db"],
  // CRITICAL
  ["critical", "rm -rf /"],
  ["critical", "rm -fr ~"],
  ["critical", "rm -Rf /"],
  ["critical", "rm -r -f /"],
  ["critical", "rm --recursive --force /"],
  ["critical", "sudo rm -rf /"],
  ["critical", "/bin/rm -rf /"],
  ["critical", 'psql -c "DROP DATABASE app"'],
  ["critical", 'mysql -e "drop table users"'],
  ["critical", 'psql -c "TRUNCATE TABLE users"'],
  ["critical", "git push --force"],
  ["critical", "git push -f origin main"],
  ["critical", "git push --force-with-lease"],
  ["critical", "git push origin +main"],
  ["critical", "git push origin :feature"],
  ["critical", "git push --delete origin feature"],
  ["critical", "git -C /repo push --force"],
  ["critical", "gh secret set API_KEY"],
  ["critical", "kubectl delete secret db-password"],
  ["critical", "vault kv put secret/app key=value"],
  ["critical", "terraform destroy"],
  ["critical", "dd if=/dev/zero of=/dev/sda"],
  ["critical", "mkfs.ext4 /dev/sda1"],
];

describe("classifyShellSegment — risk table", () => {
  it.each(TABLE)("%s: %s", (level, cmd) => {
    expect(classifyShellSegment(cmd, undefined).level).toBe(level);
  });

  it("always returns a human-readable reason", () => {
    for (const [, cmd] of TABLE) expect(classifyShellSegment(cmd, undefined).reason.length).toBeGreaterThan(0);
  });
});

describe("classifyShellSegment — production", () => {
  it("any otherwise low/medium command in production is at least high", () => {
    expect(classifyShellSegment("ls", "production").level).toBe("high");
    expect(classifyShellSegment("npm install", "production").level).toBe("high");
  });

  it("infers production from the segment itself", () => {
    expect(classifyShellSegment("kubectl get pods --context prod", undefined).level).toBe("high");
  });

  it("kubectl delete in production is critical", () => {
    expect(classifyShellSegment("kubectl delete deployment api", "production").level).toBe("critical");
    expect(classifyShellSegment("kubectl delete deployment api", "staging").level).toBe("high");
  });

  it("critical stays critical in production", () => {
    expect(classifyShellSegment("rm -rf /", "production").level).toBe("critical");
  });
});

describe("inferEnvironment", () => {
  const spec = (command?: string, args?: Record<string, unknown>) => ({
    category: "shell",
    operation: "execute",
    ...(command !== undefined ? { command } : {}),
    ...(args ? { arguments: args } : {}),
  });

  it("prefers the adapter-supplied resource.environment", () => {
    expect(inferEnvironment(spec("deploy --env prod"), { environment: "staging" })).toBe("staging");
  });

  it.each([
    "kubectl --context prod get pods",
    "deploy --env=production",
    "deploy --env=PRD",
    "ssh live-server",
    "psql -h db.prod.internal",
    "helm upgrade api ./chart -n production",
  ])("infers production from %j", (cmd) => {
    expect(inferEnvironment(spec(cmd), undefined)).toBe("production");
  });

  it("infers production from structured arguments", () => {
    expect(inferEnvironment(spec(undefined, { target: "production" }), {})).toBe("production");
  });

  it.each(["cat product.txt", "ls produce", "echo delivery", "npm run liveness-check", "git status"])(
    "does not infer production from %j",
    (cmd) => {
      expect(inferEnvironment(spec(cmd), undefined)).toBeUndefined();
    },
  );
});

describe("classifyStructured", () => {
  const s = (type: string) => {
    const [category, operation] = type.split(".") as [string, string];
    return { category, operation };
  };

  it.each<[string, RiskLevel]>([
    ["filesystem.read", "low"],
    ["filesystem.write", "medium"],
    ["filesystem.delete", "high"],
    ["git.push", "high"],
    ["git.force_push", "critical"],
    ["database.read", "low"],
    ["database.write", "high"],
    ["database.drop", "critical"],
    ["http.request", "medium"],
    ["email.send", "high"],
    ["payment.create", "critical"],
    ["cloud.deploy", "high"],
    ["secret.read", "high"],
    ["secret.write", "critical"],
    ["mcp.invoke", "medium"],
    ["custom.unknown", "medium"],
  ])("%s → %s", (type, level) => {
    expect(classifyStructured(s(type), undefined).level).toBe(level);
  });

  it("raises low/medium to high in production, keeps critical", () => {
    expect(classifyStructured(s("filesystem.read"), "production").level).toBe("high");
    expect(classifyStructured(s("mcp.invoke"), "production").level).toBe("high");
    expect(classifyStructured(s("payment.create"), "production").level).toBe("critical");
  });
});

describe("maxRisk", () => {
  it("returns the more severe risk, first on ties", () => {
    const low = { level: "low" as const, reason: "a" };
    const high = { level: "high" as const, reason: "b" };
    const high2 = { level: "high" as const, reason: "c" };
    expect(maxRisk(low, high)).toBe(high);
    expect(maxRisk(high, low)).toBe(high);
    expect(maxRisk(high, high2)).toBe(high);
  });
});
