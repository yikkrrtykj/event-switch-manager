import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { locales, translator } from './messages'
import type { Locale, Translator } from './messages'

const storageKey = 'event-switch-manager.locale'
const LanguageContext = createContext<{
  locale: Locale
  t: Translator
  setLocale: (locale: Locale) => void
} | null>(null)

function savedLocale(): Locale {
  try { return localStorage.getItem(storageKey) === 'zh-CN' ? 'zh-CN' : 'en-US' }
  catch { return 'en-US' }
}

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [locale, setLocale] = useState(savedLocale)
  const value = useMemo(() => ({ locale, t: translator(locale), setLocale }), [locale])
  useEffect(() => {
    document.documentElement.lang = locale
    document.title = value.t('brand')
    try { localStorage.setItem(storageKey, locale) }
    catch { /* The selected language still applies in memory. */ }
  }, [locale, value])
  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>
}

export function useMessages() {
  const context = useContext(LanguageContext)
  if (!context) throw new Error('Missing language context')
  return context
}

export function LanguageSelect() {
  const { locale, t, setLocale } = useMessages()
  return <label className="locale-choice">
    <span>{t('language')}</span>
    <select data-slot="select" value={locale} onChange={(event) => {
      const next = locales.find((item) => item === event.target.value)
      if (next) setLocale(next)
    }}>
      <option value="en-US" lang="en-US">{t('languageEnglish')}</option>
      <option value="zh-CN" lang="zh-CN">{t('languageSimplifiedChinese')}</option>
    </select>
  </label>
}
