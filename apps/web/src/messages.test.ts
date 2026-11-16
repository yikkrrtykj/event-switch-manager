import { describe, expect, it } from 'vitest'
import { enumLabel, translate, translator, validationCounts } from './messages'
import { describeIssue } from './planner/diagnostics'

describe('offline messages', () => {
  it('applies locale plurals and substitutes values without interpreting data as a template', () => {
    expect(validationCounts(translator('en-US'), 1, 2)).toBe('1 error · 2 warnings')
    expect(validationCounts(translator('zh-CN'), 1, 2)).toBe('1 个错误 · 2 条警告')
    expect(translate('zh-CN', 'locateIssue', { code: '{path}', path: 'physical_interfaces.0' }))
      .toBe('定位 physical_interfaces.0 处的 {path}')
  })

  it('uses safe English fallbacks for unknown keys', () => {
    expect(translate('zh-CN', 'unknown.key')).toBe('Message unavailable.')
    expect(translate('zh-CN', '__proto__', {}, 'Original message')).toBe('Original message')
    expect(enumLabel(translator('zh-CN'), 'catalyst-9300')).toBe('catalyst-9300')
  })

  it('localizes known fixed diagnostics and retains full unstructured diagnostics', () => {
    const t = translator('zh-CN')
    const issue = { path: 'physical_interfaces.0.settings.speed', code: 'port_setting_unverified',
      severity: 'WARNING' as const, message: 'Verify the requested setting on the actual interface and media' }
    expect(describeIssue(issue, 'zh-CN', t)).toBe('请在实际接口及介质上验证此设置')
    const updated = { ...issue, message: 'Check Gi1/0/1 on 192.0.2.0/24' }
    expect(describeIssue(updated, 'zh-CN', t)).toBe('英文原文：Check Gi1/0/1 on 192.0.2.0/24')
    expect(describeIssue(updated, 'en-US', translator('en-US'))).toBe(updated.message)
  })
})
