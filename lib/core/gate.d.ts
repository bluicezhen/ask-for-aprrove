import { type CommandPrefixRule, type ShellToolName } from './shell.ts';
import { type RiskResult } from './risk.ts';
export interface GateConfig {
    readonly rules: {
        readonly allow: readonly CommandPrefixRule[];
    };
}
export type GateDecision = {
    readonly kind: 'allow';
    readonly matchedPrefixes: readonly string[];
    readonly risk: RiskResult;
} | {
    readonly kind: 'manual';
    readonly reason: string;
    readonly risk?: RiskResult;
};
export declare function evaluateGate(command: string, tool: ShellToolName, config: GateConfig): GateDecision;
//# sourceMappingURL=gate.d.ts.map