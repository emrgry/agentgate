import { defineProject } from "vitest/config";

export default defineProject({
  test: {
    name: "cli",
    include: ["test/**/*.test.ts"],
    environment: "node",
    // e2e tests spawn the real CLI (tsx) as a subprocess against a fake API.
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
