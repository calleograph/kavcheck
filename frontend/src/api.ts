// Клиент REST API. Сессия — HttpOnly cookie; CSRF-токен хранится только в памяти; выбранный источник — в сессии (и дублируется заголовком).
export interface User { id: string; username: string; display_name: string; role: "admin" | "analyst" | "viewer"; is_admin: boolean; local: boolean }
export interface Me { user: User; csrf_token: string; must_change_password: boolean; current_source_id: string | null; site_name: string }
export interface SourceRef { id: string; name: string; host: string; port: number; database: string; is_active: boolean; last_check_at: string | null; last_check_ok: boolean | null; ksc_version: string | null; features: Record<string, boolean | null> }
export interface Stage { stage: string; ok: boolean | null; message: string; ms: number }
export interface DiagResult { ok: boolean; stages: Stage[]; server?: { version: string; edition: string; database: string }; features?: Record<string, { ok: boolean; title: string; missing: string[] }>; warnings?: string[]; ksc_version?: string | null; hosts?: number; test_user?: { display_name: string; username: string; role: string | null; groups: string[] } }
export interface SourceFull extends SourceRef { auth_type: string; username: string; password_set: boolean; tls_mode: string; trust_server_cert: boolean; connect_timeout_s: number; query_timeout_s: number; last_check: DiagResult | null; created_at: string }
export interface Product { product_id: number; name: string; version: string; publisher: string; platform: string; first_seen: string | null; upstream_version: string; installs: number; hosts: number }
export interface Page<T> { items: T[]; total: number; offset: number; limit: number }
export interface Host { host_id: number; name: string; fqdn: string; ip: string; os: string; os_version: string; platform: string; group: string; last_connected: string | null; last_visible: string | null; days_since_connection: number | null; activity: string; linux_release: string; rtp_state_label?: string; ksc_status?: { status: string; reasons: string[] } | null; last_av_update?: string | null; last_full_scan?: string | null; install_date?: string | null; install_id?: number }
export interface Branch { branch: string | null; installs: number; hosts: number; packages_count: number; versions: string[]; packages: { product_id: number; name: string; version: string; publisher: string; platform: string; compared_version: string }[] }
export interface Grouped { rule: { key: string; name: string; name_like: string; name_regex: string; branch_regex: string | null }; branches: Branch[]; products: number; installs: number; hosts: number; fetched_at: string }
export interface ReportParams { product_ids?: number[]; rule?: string | null; branches?: string[]; name_like?: string | null; name_regex?: string | null; min_version?: string | null; max_version?: string | null; below_version?: string | null; platform?: string | null; group_contains?: string | null; active_days?: number | null; include_inactive?: boolean; inactive_only?: boolean; q?: string | null; os_contains?: string | null }
export interface SoftwareRow { name: string; fqdn: string; ip: string; os: string; linux_release: string; platform: string; app_name: string; app_version: string; compared_version: string; branch: string; publisher: string; install_date: string | null; last_connected: string | null; days_since_connection: number | null; activity: string; group: string; host_id: number; product_id: number; install_id: number }
export interface Summary { products: number; installs_total: number; rows: number; hosts: number; excluded_inactive_hosts: number; excluded_not_computers: number; branches?: { branch: string; installs: number; hosts: number; packages: string[] }[]; active_days: number | null; include_inactive: boolean; fetched_at: string }
export interface Job { id: string; source_id: string; source_name: string; kind: "software_hosts" | "hosts"; title: string; params: ReportParams; status: "queued" | "running" | "done" | "failed" | "cancelled"; progress: string | null; created_by: string; created_at: string; started_at: string | null; finished_at: string | null; data_fetched_at: string | null; rows: number | null; summary: Summary | null; error: string | null }
export interface Template { id: string; name: string; kind: Job["kind"]; params: ReportParams; shared: boolean; owner_id: string | null; created_at: string }
export interface Check { id: string; source_id: string; name: string; selection: ReportParams; cve: string | null; severity: string; description: string | null; comment: string | null; created_by: string; created_at: string; user_defined: true }
export interface Vuln { occurrence_id: number; host_id: number; host: string; detected: string | null; kla_id: string; severity: string; cve: string; product: string; product_version: string; patches_available: boolean; url: string }
export interface AdminUser { id: string; username: string; display_name: string; email: string | null; auth_source: string; role: User["role"]; is_active: boolean; all_sources: boolean; source_ids: string[]; must_change_password: boolean; last_login_at: string | null; created_at: string }
export interface Rule { id?: string; key: string; name: string; name_like: string; name_regex: string; branch_regex: string | null; branch_parts: number; exclude_regex: string | null; description: string | null; builtin?: boolean; enabled: boolean }
export interface Dashboard { source: SourceRef; summary: { activity_days: number; hosts_total?: number; hosts_active?: number; hosts_inactive?: number; products?: number; installs?: number; ksc_version?: string | null; fetched_at: string; hosts_error?: string; software_error?: string } | null; error: string | null; reports_total: number; recent_reports: { id: string; title: string; status: string; created_at: string; rows: number | null }[] }
export interface SystemStatus { version: string; commit: string; built_at: string; public_url: string; master_key_ok: boolean; checks: Record<string, { ok: boolean; error?: string | null; running?: number; queued?: number; last_done?: string | null; optional?: boolean }>; sources: { id: string; name: string; is_active: boolean; last_check_at: string | null; last_check_ok: boolean | null; ksc_version: string | null }[]; counts: Record<string, number>; disk_free_bytes: number | null }
export interface AuditRow { id: number; at: string; actor: string; action: string; target_type: string; target_id: string; source_id: string | null; details: unknown; result: string; ip: string | null; duration_ms: number | null }
export interface JournalRow { id: number; at: string; level: string; category: string; event: string; user: string | null; source: string | null; message: string | null; data: unknown; duration_ms: number | null; ip: string | null; request_id: string | null }
export interface UpdatesOverview { installed: { version: string; commit: string; built_at: string }; updater: { available: boolean; heartbeat_age_s: number | null; state: string; action: string; step_no: number; step_total: number; step_name: string; started_at: number; finished_at: number; exit_code: number | null; result: string; request_pending: boolean; by: string; target: string }; remote: { checked_at: number; ok: boolean; error: string; current_version: string; latest_version: string; latest_tag: string; behind: boolean; notes: string; published_at: string; age_s: number } | null; history: { at: number; action: string; result: string; from_version: string; to_version: string; by: string; stage?: string }[]; backups: { name: string; size: number; at: number }[]; can_act: boolean; reasons: string[]; commands: Record<string, string> }
export type SettingsValues = Record<string, string | number | boolean | null>;

let csrf = "";
let sourceId: string | null = null;
let onUnauthorized: (() => void) | null = null;
export const setCsrf = (t: string) => { csrf = t; };
export const setSourceId = (id: string | null) => { sourceId = id; };
export const setUnauthorizedHandler = (fn: (() => void) | null) => { onUnauthorized = fn; };

export class ApiError extends Error {
  constructor(public status: number, message: string, public code = "", public retryAfter?: number) { super(message); }
}

async function req<T>(method: string, path: string, body?: unknown, opts: { raw?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && method !== "HEAD") headers["X-CSRF-Token"] = csrf;
  if (sourceId) headers["X-Source-Id"] = sourceId;
  const r = await fetch(`/api/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin" });
  if (r.status === 401 && onUnauthorized && !path.startsWith("/auth/login")) onUnauthorized();
  if (!r.ok) {
    let msg = `Ошибка ${r.status}`, code = "";
    try { const d = await r.json(); const det = d.detail; if (typeof det === "string") msg = det; else if (det && typeof det === "object") { msg = det.message ?? JSON.stringify(det); code = det.code ?? ""; } else if (Array.isArray(det)) msg = det.map((x: { msg: string; loc: unknown[] }) => `${x.loc?.slice(-1)[0]}: ${x.msg}`).join("; "); } catch { /* текст недоступен */ }
    const ra = Number(r.headers.get("Retry-After") || 0) || undefined;
    throw new ApiError(r.status, msg, code, ra);
  }
  if (r.status === 204 || opts.raw) return undefined as T;
  return r.json() as Promise<T>;
}
const qs = (o: Record<string, string | number | boolean | undefined | null>) => { const p = new URLSearchParams(); for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== null && v !== "") p.set(k, String(v)); const s = p.toString(); return s ? `?${s}` : ""; };

export const api = {
  login: (login: string, password: string) => req<Me>("POST", "/auth/login", { login, password }),
  logout: () => req<void>("POST", "/auth/logout"),
  me: () => req<Me>("GET", "/auth/me"),
  changePassword: (current_password: string, new_password: string) => req<void>("POST", "/auth/change-password", { current_password, new_password }),
  mySources: () => req<{ items: SourceRef[]; current: string | null }>("GET", "/auth/sources"),
  selectSource: (source_id: string) => req<{ current: string }>("POST", "/auth/source", { source_id }),
  version: () => req<{ version: string; commit: string; built_at: string }>("GET", "/version"),
  dashboard: (refresh = false) => req<Dashboard>("GET", `/dashboard${qs({ refresh })}`),
  software: {
    registry: (p: Record<string, string | number | boolean | undefined>) => req<Page<Product>>("GET", `/software${qs(p)}`),
    rules: () => req<{ items: { key: string; name: string; description: string | null; builtin: boolean }[] }>("GET", "/software/rules"),
    grouped: (key: string, platform = "") => req<Grouped>("GET", `/software/grouped/${encodeURIComponent(key)}${qs({ platform })}`),
    hosts: (params: ReportParams, offset = 0, limit = 100) => req<Page<SoftwareRow> & { summary: Summary; branches: Summary["branches"]; fetched_at: string }>("POST", `/software/hosts${qs({ offset, limit })}`, params),
    productHosts: (id: number) => req<{ items: Host[]; total: number; active: number; inactive: number; activity_days: number; fetched_at: string }>("GET", `/software/${id}/hosts`),
  },
  hosts: {
    list: (p: Record<string, string | number | boolean | undefined>) => req<Page<Host> & { activity_days: number; fetched_at: string }>("GET", `/hosts${qs(p)}`),
    one: (id: number) => req<{ host: Host; activity_days: number; fetched_at: string; software: { install_id: number; product_id: number; name: string; version: string; publisher: string; install_date: string | null }[]; kaspersky: { product_code: string; product: string; build: string; state: string; av_bases_date: string | null; is_av: boolean; has_rtp: boolean }[] }>("GET", `/hosts/${id}`),
  },
  vulns: (p: Record<string, string | number | undefined>) => req<Page<Vuln> & { unsupported?: string[]; approximate_total?: boolean }>("GET", `/vulnerabilities${qs(p)}`),
  reports: {
    list: (sourceOnly = true) => req<{ items: Job[] }>("GET", `/reports${qs({ source_only: sourceOnly })}`),
    create: (kind: Job["kind"], title: string, params: ReportParams) => req<Job>("POST", "/reports", { kind, title, params }),
    get: (id: string) => req<Job>("GET", `/reports/${id}`),
    rows: (id: string, offset: number, limit: number) => req<Page<SoftwareRow & Host>>("GET", `/reports/${id}/rows${qs({ offset, limit })}`),
    downloadUrl: (id: string, fmt: "csv" | "xlsx") => `/api/v1/reports/${id}/download/${fmt}`,
    cancel: (id: string) => req<Job>("POST", `/reports/${id}/cancel`),
    rerun: (id: string) => req<Job>("POST", `/reports/${id}/rerun`),
    remove: (id: string) => req<void>("DELETE", `/reports/${id}`),
    templates: () => req<{ items: Template[] }>("GET", "/report-templates"),
    saveTemplate: (name: string, kind: Job["kind"], params: ReportParams, shared = true) => req<Template>("POST", "/report-templates", { name, kind, params, shared }),
    deleteTemplate: (id: string) => req<void>("DELETE", `/report-templates/${id}`),
    checks: () => req<{ items: Check[] }>("GET", "/checks"),
    saveCheck: (body: { name: string; selection: ReportParams; cve?: string | null; severity: string; description?: string | null; comment?: string | null }) => req<Check>("POST", "/checks", body),
    deleteCheck: (id: string) => req<void>("DELETE", `/checks/${id}`),
  },
  admin: {
    users: (q = "") => req<{ items: AdminUser[] }>("GET", `/admin/users${qs({ q })}`),
    createUser: (body: Partial<AdminUser> & { password?: string }) => req<AdminUser>("POST", "/admin/users", body),
    patchUser: (id: string, body: Partial<AdminUser> & { password?: string }) => req<AdminUser>("PATCH", `/admin/users/${id}`, body),
    deleteUser: (id: string) => req<void>("DELETE", `/admin/users/${id}`),
    sources: () => req<{ items: SourceFull[] }>("GET", "/admin/sources"),
    createSource: (body: unknown) => req<SourceFull>("POST", "/admin/sources", body),
    updateSource: (id: string, body: unknown) => req<SourceFull>("PUT", `/admin/sources/${id}`, body),
    deleteSource: (id: string) => req<void>("DELETE", `/admin/sources/${id}`),
    testSource: (id: string) => req<DiagResult>("POST", `/admin/sources/${id}/test`),
    pingSource: (id: string) => req<{ ok: boolean; ms: number; error?: string }>("POST", `/admin/sources/${id}/ping`),
    settings: (group: string) => req<SettingsValues>("GET", `/admin/settings/${group}`),
    saveSettings: (group: string, body: SettingsValues) => req<SettingsValues>("PUT", `/admin/settings/${group}`, body),
    ldapTest: (test_login?: string, test_password?: string) => req<DiagResult>("POST", "/admin/ldap/test", { test_login, test_password }),
    rules: () => req<{ items: Rule[] }>("GET", "/admin/rules"),
    createRule: (body: Rule) => req<Rule>("POST", "/admin/rules", body),
    updateRule: (key: string, body: Rule) => req<Rule>("PUT", `/admin/rules/${key}`, body),
    deleteRule: (key: string) => req<void>("DELETE", `/admin/rules/${key}`),
    resetBuiltin: () => req<{ ok: boolean }>("POST", "/admin/rules/reset-builtin"),
    audit: (p: Record<string, string | number | undefined>) => req<{ items: AuditRow[] }>("GET", `/admin/audit${qs(p)}`),
    journal: (p: Record<string, string | number | undefined>) => req<{ items: JournalRow[]; errors_24h: number }>("GET", `/admin/journal${qs(p)}`),
    journalExportUrl: (range: string) => `/api/v1/admin/journal/export.csv${qs({ range })}`,
    journalPurge: () => req<{ deleted: number }>("POST", "/admin/journal/purge"),
    system: () => req<SystemStatus>("GET", "/admin/system"),
    updates: () => req<UpdatesOverview>("GET", "/admin/updates"),
    updatesCheck: () => req<{ request_id: string }>("POST", "/admin/updates/check"),
    updatesRun: (target = "") => req<{ request_id: string }>("POST", "/admin/updates/run", { confirm: true, target }),
    updatesRollback: () => req<{ request_id: string }>("POST", "/admin/updates/rollback", { confirm: true }),
    updatesBackup: () => req<{ request_id: string }>("POST", "/admin/updates/backup"),
    updatesLog: (offset: number) => req<{ offset: number; size: number; text: string; reset: boolean; state: string; step_no: number; step_total: number; step_name: string; result: string; exit_code: number | null; finished_at: number }>("GET", `/admin/updates/log${qs({ offset })}`),
  },
};
