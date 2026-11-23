import { describe, expect, it } from 'vitest'
import { canonicalJson, canonicalSha256 } from './canonical'

describe('Python-compatible canonical JSON and SHA-256', () => {
  it('matches fixed Python cross-language vectors', () => {
    const first = {
      b: 1,
      a: [3, true, null, 'line\n'],
      'é': '雪',
      nested: { z: '\\"', y: '\u2028' },
    }
    expect(canonicalJson(first)).toBe(
      '{"a":[3,true,null,"line\\n"],"b":1,"nested":{"y":"\u2028","z":"\\\\\\""},"é":"雪"}',
    )
    expect(canonicalSha256(first)).toBe(
      '7884a5de0d22b1a2e57ff831116dca60290566c0e938595728b8f5926780d062',
    )

    const second = { emoji: '😀', control: '\x01\x1f\x7f', quote: 'a"b\\c', tab: '\t' }
    expect(canonicalJson(second)).toBe(
      '{"control":"\\u0001\\u001f\x7f","emoji":"😀","quote":"a\\"b\\\\c","tab":"\\t"}',
    )
    expect(canonicalSha256(second)).toBe(
      '452a7de2ac4e404dbf2f436612921b24a030c3a38b53f986404df2d5a6c7b377',
    )
  })

  it('preserves array order while ordering object keys by code point', () => {
    expect(canonicalJson({ z: [3, 1, 2], ä: { b: 2, a: 1 } }))
      .toBe('{"z":[3,1,2],"ä":{"a":1,"b":2}}')
  })

  it('does not silently coerce non-JSON values or non-finite numbers', () => {
    expect(() => canonicalJson(Number.NaN)).toThrow()
    expect(() => canonicalJson(undefined)).toThrow()
  })
})
