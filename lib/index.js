import z from '@deepseek-ai/schemastery';
import { evaluateGate } from "./core/gate.js";
export const name = 'command-gate';
export const inject = ['approval', 'permissionPresets', 'tools'];
export const Config = z.object({
    version: z.union([1]).default(1),
    rules: z.object({ allow: z.array(z.object({ tool: z.union(['shell', 'pwsh']).required(), prefix: z.string().min(1).required() })).default([]) }).default({ allow: [] }),
    approval: z.object({ timeoutMs: z.number().step(1).min(1_000).max(120_000).default(120_000) }).default({ timeoutMs: 120_000 }),
    audit: z.object({ maxCommandChars: z.number().step(1).min(128).max(20_000).default(2_000) }).default({ maxCommandChars: 2_000 }),
});
const defaultSettings = { version: 1, rules: { allow: [] }, approval: { timeoutMs: 120_000 }, audit: { maxCommandChars: 2_000 } };
const toolDialect = (name) => name === 'bash' ? 'shell' : name === 'pwsh' ? 'pwsh' : undefined;
const commandOf = (args) => {
    if (!args || typeof args !== 'object' || Array.isArray(args))
        return undefined;
    const value = args.command;
    return typeof value === 'string' ? value : undefined;
};
const errorResult = (text) => ({ content: [{ type: 'text', text }], isError: true, error: { message: text } });
function presetOf(ctx, agent) {
    try {
        const service = ctx.permissionPresets;
        if (service && typeof service.current === 'function')
            return service.current(agent.session);
    }
    catch { /* fail closed below */ }
    return 'workspace-write';
}
export function apply(ctx, config = defaultSettings) {
    const readConfig = () => {
        try {
            const value = typeof config.get === 'function' ? config.get() : config;
            if (!value || value.version !== 1 || !value.rules || !Array.isArray(value.rules.allow))
                return defaultSettings;
            return value;
        }
        catch {
            return defaultSettings;
        }
    };
    let currentConfig = readConfig();
    const audit = (event, command, detail) => {
        const safe = command.replace(/(?:api[_-]?key|token|secret|password)=\S+/gi, '$1=[REDACTED]').slice(0, currentConfig.audit.maxCommandChars);
        console.info(`[command-gate] ${event}: ${safe} (${detail})`);
    };
    ctx.on('tools/execute', async (execution, next) => {
        const agent = execution.agent;
        if (agent === undefined)
            return errorResult('command-gate: missing agent; execution denied');
        currentConfig = readConfig();
        const dialect = toolDialect(execution.name);
        if (dialect === undefined || presetOf(ctx, agent) !== 'command-gate')
            return next();
        const command = commandOf(execution.arguments);
        if (command === undefined)
            return errorResult('command-gate: invalid shell arguments; execution denied');
        const decision = evaluateGate(command, dialect, currentConfig);
        if (decision.kind === 'allow') {
            audit('allow', command, decision.matchedPrefixes.join(', '));
            return next();
        }
        audit('approval-required', command, decision.reason);
        const request = {
            agent,
            callId: execution.callId,
            toolName: execution.name,
            reason: `command-gate approval required: ${command.slice(0, currentConfig.audit.maxCommandChars)}`,
        };
        let outcome = 'unavailable';
        const approvalAbort = new AbortController();
        const timeout = setTimeout(() => approvalAbort.abort(), currentConfig.approval.timeoutMs);
        try {
            outcome = await ctx.waterfall(agent, 'approval/request', { ...request, signal: approvalAbort.signal }, () => Promise.resolve('unavailable'));
        }
        catch {
            outcome = 'unavailable';
        }
        finally {
            clearTimeout(timeout);
        }
        if (outcome === 'allowed-once') {
            audit('approved-once', command, decision.reason);
            return next();
        }
        audit('denied', command, outcome);
        return errorResult(`command-gate: execution denied (${outcome}); command requires explicit approval`);
    }, { prepend: true });
}
export { evaluateGate } from "./core/gate.js";
export * from "./core/shell.js";
export * from "./core/risk.js";
