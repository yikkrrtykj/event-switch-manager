import { enUS } from './locales/en-US'
import { zhCN } from './locales/zh-CN'

export const locales = ['en-US', 'zh-CN'] as const
export type Locale = typeof locales[number]
export type MessageKey = keyof typeof enUS
export type MessageText = string | { one?: string; other: string }
type Values = Record<string, string | number>
export type Message = { key: MessageKey; values?: Values }
export type Translator = (message: MessageKey | Message, values?: Values) => string

const catalogs: Record<Locale, Partial<Record<MessageKey, MessageText>>> = { 'en-US': enUS, 'zh-CN': zhCN }
const plurals = {
  'en-US': new Intl.PluralRules('en-US'),
  'zh-CN': new Intl.PluralRules('zh-CN'),
}

export function translate(locale: Locale, key: string, values: Values = {}, englishFallback: string = enUS.fallback) {
  if (!Object.hasOwn(enUS, key)) return englishFallback
  const messageKey = key as MessageKey
  const translated = catalogs[locale][messageKey]
  const text = translated ?? enUS[messageKey]
  const rule = plurals[translated === undefined ? 'en-US' : locale]
  const template = typeof text === 'string' ? text
    : rule.select(Number(values.count)) === 'one' ? text.one ?? text.other : text.other
  return template.replace(/\{([a-z]+)\}/gi, (placeholder, name: string) =>
    Object.hasOwn(values, name) ? String(values[name]) : placeholder)
}

export function translator(locale: Locale): Translator {
  return (message, values) => typeof message === 'string' ? translate(locale, message, values)
    : translate(locale, message.key, message.values)
}

export const message = (key: MessageKey, values?: Values): Message => ({ key, values })

export function validationCounts(t: Translator, errors: number, warnings: number) {
  return t('validationCounts', { errors: t('errorCount', { count: errors }), warnings: t('warningCount', { count: warnings }) })
}

const values: Partial<Record<string, MessageKey>> = {
  "active": 'valueActive',
  "passive": 'valuePassive',
  "static": 'valueStatic',
  "access": 'valueAccess',
  "trunk": 'valueTrunk',
  "routed": 'valueRouted',
  "edge": 'valueEdge',
  "edge-trunk": 'valueEdgeTrunk',
  "disabled": 'valueDisabled',
  "enabled": 'valueEnabled',
  "up": 'valueUp',
  "down": 'valueDown',
  "auto": 'valueAuto',
  "full": 'valueFull',
  "half": 'valueHalf',
  "never": 'valueNever',
  "ordinary": 'valueOrdinary',
  "management": 'valueManagement',
  "guest": 'valueGuest',
  "sensitive": 'valueSensitive',
  "transit": 'valueTransit',
  "svi": 'valueSvi',
  "port-channel": 'valuePortChannel',
  "loopback": 'valueLoopback',
  "deny": 'valueDeny',
  "allow": 'valueAllow',
  "unknown": 'valueUnknown',
  "ip": 'valueIp',
  "tunnel": 'valueTunnel',
  "discard": 'valueDiscard',
  "always": 'valueAlways',
  "track": 'valueTrack',
  "route-table": 'valueRouteTable',
  "use-sbr": 'valueUseSbr',
  "cisco": 'valueCisco',
  "hillstone": 'valueHillstone',
  "other": 'valueOther',
  "core": 'valueCore',
  "external-distribution": 'valueExternalDistribution',
  "ready": 'valueReady',
  "missing": 'valueMissing',
  "verified": 'valueVerified',
}

export function enumLabel(t: Translator, value: string | number, field?: string) {
  if (field !== 'settings.admin_state' && (value === 'up' || value === 'down')) {
    return t(value === 'up' ? 'valueLinkUp' : 'valueLinkDown')
  }
  const key = Object.hasOwn(values, value) ? values[value] : undefined
  return key ? t(key) : String(value)
}

const statusKeys = { VALID: 'statusValid', VALID_WITH_WARNINGS: 'statusValidWithWarnings', INVALID: 'statusInvalid' } as const
const severityKeys = { ERROR: 'severityError', WARNING: 'severityWarning' } as const
export const statusLabel = (t: Translator, status?: keyof typeof statusKeys) =>
  status ? t(statusKeys[status]) : t('notValidated')
export const severityLabel = (t: Translator, severity: keyof typeof severityKeys) =>
  t(severityKeys[severity])
