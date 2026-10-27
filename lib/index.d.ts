import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import type { CommandPrefixRule } from './core/shell.ts';
export declare const name = "command-gate";
export declare const inject: readonly ["approval", "permissionPresets", "tools"];
export interface CommandGateSettings {
    version: 1;
    rules: {
        allow: CommandPrefixRule[];
    };
    approval: {
        timeoutMs: number;
    };
    audit: {
        maxCommandChars: number;
    };
}
export declare const Config: z<CommandGateSettings>;
export declare function apply(ctx: Context, config?: CommandGateSettings | {
    get(): CommandGateSettings;
}): void;
export { evaluateGate } from './core/gate.ts';
export * from './core/shell.ts';
export * from './core/risk.ts';
//# sourceMappingURL=index.d.ts.map