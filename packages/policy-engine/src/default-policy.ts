/** Built-in policy used when the user has no ~/.agentgate/policy.yaml. */
export const DEFAULT_POLICY_YAML = `# AgentGate policy. First matching rule wins per sub-command;
# for compound commands the most restrictive sub-command decides.
version: 1

defaults:
  low: allow
  medium: allow
  high: ask
  critical: ask
  # Shell commands that match no built-in known-safe shape (allowlist posture):
  # scripts, build tools, network clients, anything unknown.
  unrecognized: ask

rules:
  - id: deny-rm-rf
    description: recursive + forced rm in any spelling (-rf, -fr, -Rf, -r -f, --recursive --force)
    match:
      binary: rm
      flags: ["-r|-R|--recursive", "-f|--force"]
    decision: deny

  # MCP client configs: rewriting them would reroute MCP servers around the gateway.
  # Classified critical; applies to shell writes, file tools and MCP file-writing tools.
  - id: deny-mcp-self-reconfigure
    match:
      writes_to:
        - "~/Library/Application Support/Claude/claude_desktop_config.json"
        - "~/.cursor/mcp.json"
        - "**/.cursor/mcp.json"
        - "**/.mcp.json"
        - "~/.codex/config.toml"
        - "~/.claude.json"
    decision: deny

  # The gate's own config and the user's credentials / persistence points. Writing,
  # moving, truncating, chmod-ing or deleting them is denied, via shell or file tools.
  - id: deny-protected-paths
    match:
      writes_to:
        - "~/.agentgate/**"
        - "**/.claude/**"
        - "**/.git/**"
        - "**/.ssh/**"
        - "~/.bashrc"
        - "~/.bash_profile"
        - "~/.bash_login"
        - "~/.bash_logout"
        - "~/.profile"
        - "~/.zshrc"
        - "~/.zprofile"
        - "~/.zshenv"
        - "~/.zlogin"
        - "~/.zlogout"
        - "~/.kshrc"
        - "~/.cshrc"
        - "~/.tcshrc"
        - "~/.login"
        - "~/.config/fish/**"
        - "/etc/**"
        - "/private/etc/**"
        - "~/Library/LaunchAgents/**"
        - "/Library/LaunchAgents/**"
        - "/Library/LaunchDaemons/**"
        - "/var/spool/cron/**"
        - "/var/at/tabs/**"
        - "/usr/lib/cron/tabs/**"
        - "~/Library/Application Support/Claude/claude_desktop_config.json"
        - "~/.cursor/mcp.json"
        - "**/.cursor/mcp.json"
        - "**/.mcp.json"
        - "~/.codex/config.toml"
        - "~/.claude.json"
        - "~/.cursor/hooks.json"
        - "**/.cursor/hooks.json"
        - "~/.codex/hooks.json"
        - "**/.codex/hooks.json"
        - "**/.codex/config.toml"
    decision: deny

  # MCP tools that are destructive / financial / outbound / exec by name, annotation or
  # arguments always need a human, even if defaults.high is relaxed.
  - id: ask-mcp-destructive
    match: { action_type: mcp.invoke, risk_at_least: high }
    decision: ask

  - id: ask-git-push
    match: { command_prefix: "git push" }
    decision: ask

  - id: ask-kubectl-production
    match:
      contains: ["kubectl"]
      environment: production
    decision: ask

  - id: allow-git-status
    match: { command_prefix: "git status", risk_at_most: medium }
    decision: allow

  - id: allow-npm-test
    match: { command_prefix: "npm test", risk_at_most: medium }
    decision: allow

  # Common test / lint / build / typecheck entry points. They run project code, so they
  # are not on the built-in allowlist; this rule allows them explicitly.
  - id: allow-dev-scripts
    match:
      command_prefix:
        - "npm run test"
        - "npm run lint"
        - "npm run build"
        - "npm run typecheck"
        - "pnpm test"
        - "pnpm run test"
        - "pnpm run lint"
        - "pnpm run build"
        - "pnpm run typecheck"
        - "yarn test"
        - "yarn lint"
        - "yarn build"
        - "yarn typecheck"
        - "yarn run test"
        - "yarn run lint"
        - "yarn run build"
        - "yarn run typecheck"
        - "bun test"
        - "bun run test"
        - "bun run lint"
        - "bun run build"
        - "bun run typecheck"
        - "npx tsc"
      risk_at_most: medium
    decision: allow
`;
