import { describe, expect, it } from 'vitest'
import { evaluateGate } from '../src/core/gate.ts'

describe('command gate', () => {
  const rules = [
    { tool: 'shell' as const, prefix: 'git status' },
    { tool: 'shell' as const, prefix: 'aliyun ecs' },
    { tool: 'shell' as const, prefix: 'echo' },
    { tool: 'pwsh' as const, prefix: 'Get-Date' },
  ]
  it('allows a fully matched safe command', () => expect(evaluateGate('git status --short', 'shell', { rules: { allow: rules } })).toMatchObject({ kind: 'allow' }))
  it('requires every compound segment to match', () => expect(evaluateGate('echo hello; unknown', 'shell', { rules: { allow: rules } })).toMatchObject({ kind: 'manual', reason: 'no-matching-prefix' }))
  it('routes cloud mutation to approval despite matching prefix', () => expect(evaluateGate('aliyun ecs DeleteInstance --InstanceId i-x', 'shell', { rules: { allow: rules } })).toMatchObject({ kind: 'manual', reason: 'high-risk:cloud-resource-change' }))
  it('routes unsafe syntax to approval', () => expect(evaluateGate('echo $HOME', 'shell', { rules: { allow: rules } })).toMatchObject({ kind: 'manual', reason: 'unparseable:substitution-or-expansion' }))
  it('routes file deletion to approval even when echo is allowed', () => expect(evaluateGate('rm -rf /tmp/x', 'shell', { rules: { allow: [{ tool: 'shell', prefix: 'rm' }] } })).toMatchObject({ kind: 'manual', reason: 'high-risk:file-or-permission-change' }))
  it('keeps shell rules separate from pwsh', () => expect(evaluateGate('git status', 'pwsh', { rules: { allow: [] } })).toMatchObject({ kind: 'manual' }))
  it('has no default allowlist', () => expect(evaluateGate('echo hello', 'shell', { rules: { allow: [] } })).toMatchObject({ kind: 'manual' }))
})
