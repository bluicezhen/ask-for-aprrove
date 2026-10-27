# dsh-command-gate

A fail-closed shell command gate for DeepSeek Harness. Enable the `command-gate` permission preset to inspect every `bash` and `pwsh` call before its tool body runs.

## Policy

- No commands are automatically allowed by default.
- Rules are tool-specific token prefixes (`shell` maps to the `bash` tool).
- Every segment of a compound command must match.
- High-risk signals always require one-time human approval, even when a rule matches.
- Parse errors, invalid configuration, rejected/cancelled/unavailable approvals, and timeouts never execute the command.

## Configuration

Configure the plugin through its settings document:

```json
{
  "version": 1,
  "rules": {
    "allow": [
      { "tool": "shell", "prefix": "git status" },
      { "tool": "shell", "prefix": "aliyun ecs DescribeInstances" },
      { "tool": "pwsh", "prefix": "Get-Date" }
    ]
  },
  "approval": { "timeoutMs": 120000 },
  "audit": { "maxCommandChars": 2000 }
}
```

The plugin is deliberately conservative: it does not use regular expressions or LLM review, and it does not treat unknown cloud actions as safe.
