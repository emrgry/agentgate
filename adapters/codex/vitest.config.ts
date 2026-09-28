import { defineProject } from "vitest/config";

export default defineProject({ test: { name: "adapter-codex", include: ["test/**/*.test.ts"], environment: "node" } });
