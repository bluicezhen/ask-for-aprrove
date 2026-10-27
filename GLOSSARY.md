# DSH Shell Command Gate

A DSH plugin context that controls shell command execution with explicit allowlisting and human approval for anything not safely auto-allowed.

## Language

**Shell Command**:
A command submitted to the DSH `bash` or `pwsh` execution tool.
_Avoid_: Network operation, tool call (these may be broader than shell execution).

**Command Segment**:
One executable portion of a shell invocation, separated from other portions by shell control operators such as `;`, `&&`, or `||`.
_Avoid_: Partial command.

**Allow Rule**:
A tool-specific token-prefix rule that identifies shell command segments permitted to execute automatically.
_Avoid_: Approval rule, regex rule, whitelist pattern.

**Command Gate**:
The opt-in execution policy that evaluates every shell invocation before its tool body runs.
_Avoid_: Sandbox gate, approval plugin.

**High-Risk Signal**:
A deterministic property of a command that prevents automatic allowance and requires human approval, even when an allow rule matches.
_Avoid_: Dangerous command (too vague), blacklist.

**Manual Approval**:
A single explicit user decision for the complete current shell tool call; only an affirmative approval permits execution.
_Avoid_: Auto-approval, session approval.

**Fail-Closed**:
The policy that parsing errors, invalid configuration, unavailable approval, rejection, cancellation, or timeout never result in shell execution.
_Avoid_: Best-effort fallback.
