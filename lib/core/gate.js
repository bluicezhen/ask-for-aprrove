import { evaluateCommandRules, parseShellCommand } from "./shell.js";
import { detectFixedHighRisk } from "./risk.js";
export function evaluateGate(command, tool, config) {
    const parsed = parseShellCommand(command, tool);
    if (!parsed.ok)
        return { kind: 'manual', reason: `unparseable:${parsed.reason}` };
    const risk = detectFixedHighRisk(command, parsed.command.segments);
    const rules = evaluateCommandRules(command, tool, config.rules.allow ?? []);
    if (!risk.safe)
        return { kind: 'manual', reason: `high-risk:${risk.signals.join(',')}`, risk };
    if (rules.status !== 'matched')
        return { kind: 'manual', reason: rules.reason, risk };
    return { kind: 'allow', matchedPrefixes: rules.matchedPrefixes, risk };
}
