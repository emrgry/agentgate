import { defineProject } from "vitest/config";

export default defineProject({
  test: { name: "adapter-claude-code", include: ["test/**/*.test.ts"], environment: "node" },
});
