/** Supported shell tools for deterministic approval rules. */
export type ShellToolName = "shell" | "pwsh";
/** Host tool names that can emit sandbox-widening approvals. */
export type HostShellToolName = "bash" | "pwsh";
/** A shell command split into independently checked command segments. */
export interface ParsedShellCommand {
    /** Shell syntax used while tokenizing the command. */
    dialect: ShellToolName;
    /** Tokenized commands separated by control operators. */
    segments: readonly (readonly string[])[];
}
/** Failure categories that require native human approval. */
export type ShellParseFailure = "empty-command" | "empty-segment" | "unterminated-quote" | "trailing-escape" | "substitution-or-expansion" | "redirection" | "wildcard" | "grouping-or-background" | "comment" | "multiline-command" | "environment-assignment";
/** Result of parsing an untrusted shell command. */
export type ShellParseResult = {
    readonly ok: true;
    readonly command: ParsedShellCommand;
} | {
    readonly ok: false;
    readonly reason: ShellParseFailure;
};
/** One deterministic command-prefix rule. */
export interface CommandPrefixRule {
    /** Shell tool to which the prefix applies. */
    tool: ShellToolName;
    /** Literal token prefix. Shell syntax and wildcards are not supported. */
    prefix: string;
}
/** Result of evaluating every command segment against configured prefixes. */
export type RuleEvaluation = {
    readonly status: "matched";
    readonly segmentCount: number;
    readonly matchedPrefixes: readonly string[];
} | {
    readonly status: "manual";
    readonly reason: "unparseable-command" | "invalid-rule" | "no-matching-prefix";
    readonly detail?: ShellParseFailure;
};
/** Context captured when a shell tool asks to widen its sandbox. */
export interface ShellExecutionContext {
    /** Exact Harness agent object attached to the tool execution. */
    agent: unknown;
    /** Opaque tool-call identifier. */
    callId: string;
    /** Shell tool being executed. */
    toolName: string;
    /** Original lossless-JSON tool arguments. */
    args: unknown;
}
/** Approval event fields used to correlate a sandbox-widening request. */
export interface ShellApprovalRequest {
    /** Exact Harness agent object attached to the approval event. */
    agent: unknown;
    /** Opaque tool-call identifier associated with the event. */
    callId?: string;
    /** Tool name associated with the event. */
    toolName: string;
    /** Human-facing reason emitted by the sandbox escalation helper. */
    reason?: string;
}
/** A strictly associated sandbox escalation. */
export interface AssociatedShellEscalation {
    /** Exact Harness agent object shared by both events. */
    agent: object;
    /** Opaque tool-call identifier. */
    callId: string;
    /** Supported shell tool. */
    toolName: ShellToolName;
    /** Command whose escalation is under review. */
    command: string;
    /** Exact tool-provided justification. */
    justification: string;
    /** Requested sandbox permission validated by the Host. */
    requestedPermission: "workspace-write" | "danger-full-access";
}
/** Result of correlating an approval event with a shell execution. */
export type EscalationAssociation = {
    readonly status: "associated";
    readonly escalation: AssociatedShellEscalation;
} | {
    readonly status: "manual";
    readonly reason: "invalid-context" | "unsupported-tool" | "identity-mismatch" | "not-verified-widening" | "invalid-justification" | "reason-mismatch";
};
/**
 * Parses only the shell subset that can be matched without executing or expanding it.
 *
 * @param source Untrusted command string.
 * @param dialect Shell syntax to recognize.
 * @returns Parsed command segments, or a reason requiring human approval.
 */
export declare function parseShellCommand(source: string, dialect: ShellToolName): ShellParseResult;
/**
 * Checks whether a configured prefix is a single literal command prefix.
 *
 * @param rule Rule supplied by settings.
 * @returns Parsed tokens, or a reason that makes the settings invalid.
 */
export declare function validateCommandPrefix(rule: CommandPrefixRule): {
    readonly ok: true;
    readonly tokens: readonly string[];
} | {
    readonly ok: false;
    readonly reason: ShellParseFailure | "multiple-segments";
};
/**
 * Requires every command segment to match a literal token prefix for its shell.
 *
 * @param command Untrusted command under review.
 * @param tool Shell tool that will execute the command.
 * @param rules Configured positive allowlist.
 * @returns A match only when every segment is covered by a valid rule.
 */
export declare function evaluateCommandRules(command: string, tool: ShellToolName, rules: readonly CommandPrefixRule[]): RuleEvaluation;
/**
 * Correlates an approval request with the exact shell call that requested host access.
 *
 * @param execution Captured tool execution.
 * @param approval Approval event emitted for that execution.
 * @param verifiedWidening Whether the Host proved the requested mode widens the resolved sandbox policy.
 * @returns An associated escalation only for an exact, Host-verified widening.
 */
export declare function associateShellEscalation(execution: ShellExecutionContext, approval: ShellApprovalRequest, verifiedWidening: boolean): EscalationAssociation;
//# sourceMappingURL=shell.d.ts.map