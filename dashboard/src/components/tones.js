// Frozen enum values (shared/contracts.py) mapped to the status tones in ui.jsx.

export const HEALTH_TONE = { Excellent: 'ok', Good: 'info', Fair: 'warn', Poor: 'crit' }
export const SEVERITY_TONE = { low: 'neutral', medium: 'warn', high: 'crit', critical: 'crit' }
export const REMEDIATION_TONE = {
  AWAITING_APPROVAL: 'warn',
  APPROVED_EXECUTED: 'ok',
  ROLLED_BACK: 'info',
  POLICY_BLOCKED: 'crit',
}
export const REMEDIATION_LABEL = {
  AWAITING_APPROVAL: 'Awaiting approval',
  APPROVED_EXECUTED: 'Executed',
  ROLLED_BACK: 'Rolled back',
  POLICY_BLOCKED: 'Policy blocked',
}
