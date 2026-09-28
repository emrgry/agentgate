Real `claude -p … --output-format stream-json --verbose` output captured from Claude Code
2.1.283 (`--model haiku`, 2026-09-26), sanitized: local paths replaced, MCP/plugin/skill
lists, thinking signatures and rate-limit details removed. Structure and field names are
unchanged.

- `text-hello.jsonl`: single text reply (`result/success`, `num_turns: 1`)
- `tool-use.jsonl`: Bash tool_use → tool_result → text (`num_turns: 2`)
- `resume-question.jsonl`: `--resume <same session_id>`, ends with a question;
  `system/post_turn_summary.status_category = "blocked"` + `needs_action`
- `resume-missing-session.jsonl`: `--resume` of an unknown id → only a
  `result/error_during_execution` line with `is_error: true`, `num_turns: 0`, `errors[]`; exit code 1
- `not-logged-in.jsonl`: run with a minimal env lacking USER/LOGNAME (like a launchd agent) —
  `result` has `subtype: "success"` **and** `is_error: true`, reason in `result`,
  `terminal_reason: "api_error"`; exit code 1. The supervisor therefore gives turns USER/LOGNAME.
