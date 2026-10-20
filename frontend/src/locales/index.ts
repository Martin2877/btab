import type { App } from 'vue';
import { createI18n } from 'vue-i18n';
import zhCN from './zh-CN';
import enUS from './en-US';

export type AppLocale = 'zh-CN' | 'en-US';
export const LOCALE_KEY = 'btab-locale';

export function getLocale(): AppLocale {
  const v = localStorage.getItem(LOCALE_KEY);
  return v === 'en-US' ? 'en-US' : 'zh-CN';
}

export const i18n = createI18n({
  legacy: false,
  globalInjection: true,
  locale: getLocale(),
  fallbackLocale: 'zh-CN',
  messages: {
    'zh-CN': zhCN,
    'en-US': enUS,
  },
});

export function setupI18n(app: App) {
  app.use(i18n);
}

export function setLocale(locale: AppLocale) {
  i18n.global.locale.value = locale;
  localStorage.setItem(LOCALE_KEY, locale);
}

// tt 路由/菜单文案翻译：有对应 key 则翻译，否则回退原中文标题
export function tt(key: string, fallback?: string): string {
  const t = i18n.global.t;
  const te = i18n.global.te.bind(i18n.global);
  return te(key) ? t(key) : (fallback ?? key);
}
