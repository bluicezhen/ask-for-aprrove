import { evaluateCommandRules, parseShellCommand, type CommandPrefixRule, type ShellToolName } from './shell.ts'
import { detectFixedHighRisk, type RiskResult } from './risk.ts'

export interface GateConfig { readonly rules: { readonly allow: readonly CommandPrefixRule[] } }
export type GateDecision =
  | { readonly kind: 'allow'; readonly matchedPrefixes: readonly string[]; readonly risk: RiskResult }
  | { readonly kind: 'manual'; readonly reason: string; readonly risk?: RiskResult }

export function evaluateGate(command: string, tool: ShellToolName, config: GateConfig): GateDecision {
  const parsed = parseShellCommand(command, tool)
  if (!parsed.ok) return { kind: 'manual', reason: `unparseable:${parsed.reason}` }
  const risk = detectFixedHighRisk(command, parsed.command.segments)
  const rules = evaluateCommandRules(command, tool, config.rules.allow ?? [])
  if (!risk.safe) return { kind: 'manual', reason: `high-risk:${risk.signals.join(',')}`, risk }
  if (rules.status !== 'matched') return { kind: 'manual', reason: rules.reason, risk }
  return { kind: 'allow', matchedPrefixes: rules.matchedPrefixes, risk }
}
