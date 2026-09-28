import { defineConfig } from "vitest/config";

/**
 * Root test config. Each workspace gets its own project; `npx vitest run` at the root
 * runs all of them. Apps (api, daemon, mobile) can add an entry here — or their own
 * `vitest.config.ts` referenced by path — without touching the package projects.
 */
export default defineConfig({
  test: {
    projects: [
      "daemon/agentgate/vitest.config.ts",
      "adapters/claude-code/vitest.config.ts",
      "adapters/codex/vitest.config.ts",
      "adapters/generic/vitest.config.ts",
      "adapters/cursor/vitest.config.ts",
      {
        // Opt-in (AGENTGATE_RELEASE_E2E=1, macOS): builds + installs real release tarballs.
        test: {
          name: "release-e2e",
          include: ["scripts/test/**/*.test.ts"],
          environment: "node",
          testTimeout: 300_000,
          hookTimeout: 600_000,
        },
      },
      {
        test: {
          name: "packages",
          include: ["packages/**/test/**/*.test.ts"],
          environment: "node",
        },
      },
    ],
  },
});
