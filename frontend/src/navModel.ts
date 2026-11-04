/** Единая модель навигации KAV Checker: меню, группы администрирования, указатель функций для поиска, каталог быстрых действий и готовых отчётов.
 *  Любой маршрут и любая вкладка администрирования обязаны быть здесь (проверяет backend/tests/test_nav_model.py): так функция не может «потеряться» при перестройке меню. */
import type { IconName } from "./components/Icons";
import type { QuickScopeOpts } from "./components/QuickReport";
import type { QuickKind } from "./api";

export type Role = "viewer" | "analyst" | "admin";
export interface NavItem { to: string; label: string; icon: IconName; end?: boolean; roles?: Role[]; hier?: boolean }
export interface NavGroup { id: string; label: string; icon: IconName; items: NavItem[] }

export const NAV_TOP: NavItem[] = [
  { to: "/", label: "Быстрый доступ", icon: "bolt", end: true },
  { to: "/overview", label: "Обзор", icon: "home" },
];
export const NAV_GROUPS: NavGroup[] = [
  { id: "infra", label: "Инфраструктура", icon: "monitor", items: [
    { to: "/hosts", label: "Компьютеры", icon: "monitor" }, { to: "/software", label: "Программы", icon: "layers" }, { to: "/devices", label: "Устройства и пользователи", icon: "users" }] },
  { id: "sec", label: "Защита и уязвимости", icon: "shieldPulse", items: [
    { to: "/protection", label: "Состояние защиты", icon: "shieldPulse" }, { to: "/vulnerabilities", label: "Уязвимости", icon: "bug" }, { to: "/vdb", label: "База уязвимостей", icon: "vault" },
    { to: "/eol", label: "EOL", icon: "clock" }, { to: "/events", label: "События безопасности", icon: "bell" },
    { to: "/hunt", label: "CVE Hunt", icon: "search", roles: ["analyst", "admin"] }, { to: "/pentest", label: "Pentest", icon: "target", roles: ["analyst", "admin"] }] },
  { id: "org", label: "Организация", icon: "sitemap", items: [
    { to: "/zones", label: "Зоны ответственности", icon: "grid" }, { to: "/hierarchy", label: "Иерархия предприятия", icon: "sitemap", hier: true }] },
];
export const NAV_REPORTS: NavItem = { to: "/reports", label: "Отчёты", icon: "file" };
/** Маршруты, которые не попадают в меню: вложенные страницы, личные страницы, служебные. */
export const NAV_HIDDEN: Record<string, string> = {
  "/software/p/:key": "карточка программы (из «Программы», поиска, отчётов)", "/hosts/:hostId": "карточка компьютера (из «Компьютеры», поиска)", "/vulnerabilities/hosts/:hostId": "уязвимости компьютера (из «Уязвимости»)",
  "/zones/:zid": "карточка зоны (из «Зоны ответственности»)", "/reports/:jobId": "готовый отчёт (из «Отчёты»)", "/security": "личная страница: пароль и двухфакторная проверка (меню пользователя)",
  "/appearance": "личная страница: тема оформления (меню пользователя)", "/password": "перенаправление на /security", "/admin": "администрирование (группа меню «Администрирование»)",
};

export const ADMIN_TABS: { id: string; label: string }[] = [
  { id: "system", label: "Техническое состояние" }, { id: "sources", label: "Источники данных" }, { id: "licenses", label: "Лицензии" }, { id: "users", label: "Пользователи" }, { id: "ldap", label: "LDAPS" }, { id: "hier", label: "Иерархия предприятия" },
  { id: "general", label: "Общие настройки" }, { id: "zones", label: "Зоны ответственности" }, { id: "zcache", label: "Расчёт данных зон" }, { id: "eolcfg", label: "EOL и пользователи" }, { id: "mail", label: "Рассылки отчётов" }, { id: "org", label: "Организация и отчёты" },
  { id: "catalog", label: "Каталог программ" }, { id: "vdb", label: "База уязвимостей" }, { id: "pentest", label: "Pentest" }, { id: "ptchecks", label: "Pentest: шаблоны и проверки" }, { id: "updates", label: "Обновления" }, { id: "components", label: "Компоненты" },
  { id: "journal", label: "Журнал событий" }, { id: "audit", label: "Журнал действий" }, { id: "logs", label: "Журналы и хранение" },
];
export const ADMIN_GROUPS: { id: string; label: string; tabs: string[] }[] = [
  { id: "conn", label: "Подключения и источники", tabs: ["sources", "ldap", "licenses"] },
  { id: "access", label: "Пользователи и доступ", tabs: ["users"] },
  { id: "org", label: "Организация", tabs: ["hier", "zones", "zcache", "org"] },
  { id: "rules", label: "Правила анализа", tabs: ["eolcfg", "catalog", "vdb", "pentest", "ptchecks"] },
  { id: "system", label: "Система и обслуживание", tabs: ["system", "general", "updates", "components"] },
  { id: "logs", label: "Журналы и уведомления", tabs: ["journal", "audit", "logs", "mail"] },
];
export const ADMIN_ICONS: Record<string, IconName> = { system: "gauge", sources: "database", licenses: "key", users: "users", ldap: "key", hier: "sitemap", general: "sliders", zones: "grid", zcache: "clock", eolcfg: "users", mail: "mail", org: "file",
  catalog: "package", vdb: "vault", pentest: "target", ptchecks: "shieldPulse", updates: "upload", components: "package", journal: "journal", audit: "history", logs: "database" };

// ------------------------------------------------------------------------------------------------ указатель функций (поиск по названию и ключевым словам)
export interface Fn { title: string; to: string; kw: string; icon: IconName; roles?: Role[]; hier?: boolean; group: string }
const ADMIN_KW: Record<string, string> = {
  system: "состояние здоровье контейнеры задания очереди postgres диагностика ресурсы память диск ошибки сервер", sources: "подключение ksc sql bi smb excel выгрузка импорт bi источник данных сопоставление структура файла", licenses: "лицензия ключ срок kaspersky",
  users: "пользователь роль права доступ учётная запись пароль двухфакторная 2fa", ldap: "ldaps active directory ad домен вход сертификат группы доступа", hier: "иерархия адресная книга exchange подразделения руководитель очистка правила роли отчётов порог большая группа",
  general: "общие настройки активность период хранение ограничения отчётов название сайта", zones: "зоны ответственные csv импорт спорные компьютеры исключения", zcache: "расчёт зон расписание ресурсы кэш ночной", eolcfg: "eol окончание поддержки исключения опрос пользователей устройств пороги cpu озу",
  mail: "рассылка отчётов почта smtp расписание", org: "организация шапка подвал логотип отчёты оформление", catalog: "каталог программ продукты ветки группировка исправления", vdb: "база уязвимостей nvd kev osv бду фстэк источники обновление",
  pentest: "pentest профили сканирование nmap", ptchecks: "nuclei шаблоны проверки nse политика безопасности", updates: "обновление версия релиз откат резервная копия", components: "компоненты версии зависимости обновление решения",
  journal: "журнал событий ошибки входы запросы", audit: "журнал действий кто что сделал аудит", logs: "журналы хранение ротация квота архивы сроки",
};
const NAV_KW: Record<string, string> = {
  "/": "быстрый доступ старт избранное главная панель", "/overview": "обзор главная сводка показатели лицензии динамика", "/hosts": "компьютеры устройства рабочие станции серверы состояние найти компьютер", "/software": "программы версии установленное по реестр найти программу",
  "/devices": "устройства пользователи владелец bi сопоставление сотрудники владельцы принадлежность", "/protection": "защита антивирус базы постоянная защита проблемные компьютеры состояние защиты", "/vulnerabilities": "уязвимости cve kla исправления обнаружения отчёт по уязвимостям игнорировать исключения",
  "/vdb": "база уязвимостей cve nvd kev osv бду поиск план устранения", "/eol": "eol окончание поддержки операционные системы устаревшие исключения", "/events": "события безопасности угрозы обнаружения атаки", "/hunt": "cve hunt целевой поиск уязвимости задание",
  "/pentest": "pentest сканирование находки результаты задания nmap nuclei", "/zones": "зоны ответственности ответственные контакты компьютеры зоны", "/hierarchy": "иерархия предприятия структура организации руководители подразделения граф", "/reports": "отчёты сформированные проверка версий шаблоны сохранённые центр отчётов",
};
const ROLE_ADMIN: Role[] = ["admin"];
const GROUP_OF = (p: string) => NAV_GROUPS.find((g) => g.items.some((i) => i.to === p))?.label ?? (p === "/" || p === "/overview" ? "Главное" : "Отчёты");
export const FUNCTIONS: Fn[] = [
  ...[...NAV_TOP, ...NAV_GROUPS.flatMap((g) => g.items), NAV_REPORTS].map((n): Fn => ({ title: n.label, to: n.to, kw: NAV_KW[n.to] ?? "", icon: n.icon, roles: n.roles, hier: n.hier, group: GROUP_OF(n.to) })),
  ...ADMIN_TABS.map((t): Fn => ({ title: t.label, to: `/admin?tab=${t.id}`, kw: ADMIN_KW[t.id] ?? "", icon: ADMIN_ICONS[t.id], roles: ROLE_ADMIN, group: `Администрирование · ${ADMIN_GROUPS.find((g) => g.tabs.includes(t.id))?.label ?? ""}` })),
  { title: "Владельцы устройств (BI)", to: "/devices?tab=bi", kw: "владелец сотрудник bi принадлежность история устройства", icon: "users", group: "Инфраструктура" },
  { title: "Сопоставление BI и KSC", to: "/devices?tab=match", kw: "сопоставление bi ksc совпадения подтвердить расхождения владелец", icon: "branch", group: "Инфраструктура" },
  { title: "Пользователи KSC", to: "/devices?tab=ksc", kw: "пользователи ksc вход последний пользователь логин", icon: "users", group: "Инфраструктура" },
  { title: "Active Directory: пользователи и группы", to: "/hierarchy?tab=ad", kw: "active directory ad домен учётная запись группы членство memberof участники группы пользователь домена логин upn dn", icon: "users", roles: ["analyst", "admin"], hier: true, group: "Организация" },
  { title: "Импорт BI-выгрузки", to: "/admin?tab=sources", kw: "импорт bi выгрузка excel smb структура проверить запустить", icon: "upload", roles: ROLE_ADMIN, group: "Администрирование · Подключения и источники" },
  { title: "Новая проверка версий программ", to: "/reports", kw: "проверка версий устаревшие версии программ отчёт аудит", icon: "file", group: "Отчёты" },
  { title: "Моя тема оформления", to: "/appearance", kw: "тема оформления night glass grove aurora цвет", icon: "sun", group: "Личное" },
  { title: "Безопасность учётной записи", to: "/security", kw: "пароль смена пароля двухфакторная 2fa totp резервные коды", icon: "key", group: "Личное" },
];

// ------------------------------------------------------------------------------------------------ быстрый доступ
export interface QuickAction { id: string; title: string; hint: string; icon: IconName; to?: string; search?: "hosts" | "software" | "users" | "vuln"; roles?: Role[]; hier?: boolean }
export const QUICK_ACTIONS: QuickAction[] = [
  { id: "find-host", title: "Найти компьютер", hint: "по имени, IP или группе", icon: "monitor", search: "hosts" },
  { id: "find-software", title: "Найти программу", hint: "версии и где установлена", icon: "layers", search: "software" },
  { id: "find-user", title: "Найти пользователя", hint: "владелец и устройства", icon: "users", search: "users" },
  { id: "find-vuln", title: "Найти уязвимость или CVE", hint: "CVE, KLA, БДУ", icon: "bug", search: "vuln" },
  { id: "protection", title: "Состояние защиты", hint: "проблемы Kaspersky по компьютерам", icon: "shieldPulse", to: "/protection" },
  { id: "problem-hosts", title: "Проблемные компьютеры", hint: "защита не работает", icon: "alert", to: "/protection?problem=rtp_off" },
  { id: "devices", title: "Устройства и владельцы", hint: "кто чем пользуется", icon: "users", to: "/devices" },
  { id: "zones", title: "Зоны ответственности", hint: "ответственные и состояние зон", icon: "grid", to: "/zones" },
  { id: "pentest", title: "Результаты Pentest", hint: "задания и находки", icon: "target", to: "/pentest", roles: ["analyst", "admin"] },
  { id: "bi-match", title: "Сопоставление BI и KSC", hint: "расхождения и решения", icon: "branch", to: "/devices?tab=match" },
  { id: "vulns", title: "Уязвимости", hint: "найденные KSC и их исправления", icon: "bug", to: "/vulnerabilities" },
  { id: "hunt", title: "CVE Hunt", hint: "целевой поиск уязвимости", icon: "search", to: "/hunt", roles: ["analyst", "admin"] },
  { id: "events", title: "События безопасности", hint: "угрозы и обнаружения", icon: "bell", to: "/events" },
  { id: "eol", title: "EOL", hint: "ПО и ОС без поддержки", icon: "clock", to: "/eol" },
  { id: "hier", title: "Иерархия предприятия", hint: "структура и отчёты", icon: "sitemap", to: "/hierarchy", hier: true },
  { id: "reports", title: "Отчёты", hint: "готовые и новые", icon: "file", to: "/reports" },
  { id: "overview", title: "Обзор инфраструктуры", hint: "сводные показатели", icon: "home", to: "/overview" },
  { id: "admin-sources", title: "Источники данных", hint: "KSC и BI", icon: "database", to: "/admin?tab=sources", roles: ["admin"] },
  { id: "admin-system", title: "Техническое состояние", hint: "службы, задания, ошибки", icon: "gauge", to: "/admin?tab=system", roles: ["admin"] },
  { id: "admin-audit", title: "Журнал действий", hint: "кто и что сделал", icon: "history", to: "/admin?tab=audit", roles: ["admin"] },
];
/** Стартовые наборы: что видит пользователь до персональной настройки (с учётом ролей). */
export const DEFAULT_ITEMS: Record<Role, string[]> = {
  viewer: ["find-host", "find-software", "find-vuln", "protection", "problem-hosts", "vulns", "devices", "zones"],
  analyst: ["find-host", "find-software", "find-user", "find-vuln", "protection", "problem-hosts", "devices", "bi-match", "zones", "pentest"],
  admin: ["find-host", "find-software", "find-user", "find-vuln", "protection", "problem-hosts", "devices", "bi-match", "zones", "pentest", "admin-sources", "admin-system"],
};

export interface QuickReportDef { id: string; title: string; hint: string; icon: IconName; kind?: QuickKind; params: Record<string, unknown>; options: QuickScopeOpts; section: string; roles?: Role[]; needsSource?: boolean }
/** Готовые отчёты — только реально существующие виды. С `kind` — «Настроить» открывает тот же конструктор с фильтрами; без `kind` отчёт строится в самом разделе (нужен выбор программы, зоны или подразделения), карточка ведёт туда. */
export const QUICK_REPORTS: QuickReportDef[] = [
  { id: "r-rtp", title: "Компьютеры без работающей защиты", hint: "постоянная защита остановлена", icon: "shieldPulse", kind: "quick_protection", params: { problem: "rtp_off" }, options: { scope: true, zoneFilter: true }, section: "/protection?problem=rtp_off", needsSource: true },
  { id: "r-noav", title: "Компьютеры без антивируса", hint: "нет продукта Kaspersky", icon: "alert", kind: "quick_protection", params: { problem: "no_av" }, options: { scope: true, zoneFilter: true }, section: "/protection?problem=no_av", needsSource: true },
  { id: "r-bases", title: "Компьютеры с устаревшими базами", hint: "базы старше порога", icon: "clock", kind: "quick_protection", params: { problem: "bases_old" }, options: { scope: true, zoneFilter: true }, section: "/protection?problem=bases_old", needsSource: true },
  { id: "r-vulns", title: "Компьютеры с выявленными уязвимостями", hint: "критические по данным KSC", icon: "bug", kind: "quick_vulns", params: { severity: "critical" }, options: { scope: true, severity: true, patchable: true }, section: "/vulnerabilities", needsSource: true },
  { id: "r-hosts", title: "Компьютеры: состояние, ПО, уязвимости", hint: "все компьютеры источника", icon: "monitor", kind: "quick_hosts", params: {}, options: { sections: true, scope: true }, section: "/hosts", needsSource: true },
  { id: "r-soft", title: "Программы и их версии", hint: "где установлено, какие версии", icon: "layers", params: {}, options: {}, section: "/software", needsSource: true },
  { id: "r-devices", title: "Устройства и пользователи", hint: "кто и где работал", icon: "users", kind: "quick_devices", params: {}, options: { scope: false }, section: "/devices" },
  { id: "r-owners", title: "Устройства и владельцы (BI)", hint: "владельцы по выгрузке BI", icon: "users", kind: "quick_bi", params: { view: "owners" }, options: { scope: false, bi: true }, section: "/devices?tab=bi", roles: ["analyst", "admin"] },
  { id: "r-bi-disc", title: "Расхождения BI и KSC", hint: "противоречия и неоднозначные", icon: "branch", kind: "quick_bi", params: { view: "discrepancies" }, options: { scope: false, bi: true }, section: "/devices?tab=match", roles: ["analyst", "admin"] },
  { id: "r-eol", title: "EOL в инфраструктуре", hint: "ПО и ОС без поддержки", icon: "clock", kind: "quick_eol", params: {}, options: { scope: false, eol: true, zoneFilter: true }, section: "/eol" },
  { id: "r-events", title: "События безопасности", hint: "за 7 суток", icon: "bell", kind: "quick_events", params: { days: 7 }, options: { period: true, scope: false }, section: "/events", needsSource: true },
  { id: "r-overview", title: "Сводка инфраструктуры", hint: "показатели главной страницы", icon: "home", kind: "quick_overview", params: {}, options: { scope: false }, section: "/overview", needsSource: true },
  { id: "r-hunt", title: "Результаты CVE Hunt", hint: "история заданий", icon: "search", kind: "quick_hunt", params: { view: "jobs" }, options: { scope: false }, section: "/hunt", roles: ["analyst", "admin"] },
  { id: "r-pentest", title: "Результаты Pentest", hint: "задания и находки", icon: "target", kind: "quick_pentest", params: { view: "jobs" }, options: { scope: false }, section: "/pentest", roles: ["analyst", "admin"] },
  { id: "r-zones", title: "Зоны ответственности", hint: "состояние безопасности зон", icon: "grid", params: {}, options: {}, section: "/zones" },
  { id: "r-hier", title: "Структура организации", hint: "готовые отчёты по иерархии", icon: "sitemap", params: {}, options: {}, section: "/hierarchy", roles: ["analyst", "admin"] },
];
export const DEFAULT_REPORTS: Record<Role, string[]> = {
  viewer: ["r-rtp", "r-bases", "r-vulns", "r-hosts", "r-devices", "r-eol"],
  analyst: ["r-rtp", "r-bases", "r-vulns", "r-soft", "r-owners", "r-bi-disc", "r-zones", "r-hunt", "r-pentest"],
  admin: ["r-rtp", "r-bases", "r-vulns", "r-soft", "r-owners", "r-bi-disc", "r-zones", "r-hunt", "r-pentest"],
};

export const roleOk = (roles: Role[] | undefined, role: string) => !roles || (roles as string[]).includes(role);
