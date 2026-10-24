// Клиент REST API. Сессия — HttpOnly cookie; CSRF-токен хранится только в памяти; выбранный источник — в сессии (и дублируется заголовком).
export interface User { id: string; username: string; display_name: string; role: "admin" | "analyst" | "viewer"; is_admin: boolean; local: boolean }
export interface Me { user: User; csrf_token: string; must_change_password: boolean; current_source_id: string | null; site_name: string; activity_days: number; must_enroll_totp: boolean; totp_enabled: boolean; second_factor: string | null; secure_cookie: boolean }
export interface SourceRef { id: string; name: string; host: string; port: number; database: string; is_active: boolean; last_check_at: string | null; last_check_ok: boolean | null; ksc_version: string | null; features: Record<string, boolean | null> }
export interface Stage { stage: string; ok: boolean | null; message: string; ms: number }
export interface DiagResult { ok: boolean; stages: Stage[]; server?: { version: string; edition: string; database: string }; features?: Record<string, { ok: boolean; title: string; missing: string[] }>; warnings?: string[]; ksc_version?: string | null; hosts?: number; test_user?: { display_name: string; username: string; role: string | null; groups: string[] } }
export interface SourceFull extends SourceRef { auth_type: string; username: string; password_set: boolean; tls_mode: string; trust_server_cert: boolean; connect_timeout_s: number; query_timeout_s: number; last_check: DiagResult | null; created_at: string }
export interface Product { product_id: number; name: string; version: string; publisher: string; platform: string; first_seen: string | null; upstream_version: string; installs: number; hosts: number }
export interface Page<T> { items: T[]; total: number; offset: number; limit: number }
export interface Host { host_id: number; name: string; fqdn: string; ip: string; os: string; os_version: string; platform: string; group: string; last_connected: string | null; last_visible: string | null; online?: boolean | null; days_since_connection: number | null; activity: string; linux_release: string; rtp_state_label?: string; ksc_status?: { status: string; reasons: string[] } | null; protection?: { problems: ProblemKey[]; bases_days: number; scan_days: number } | null; last_av_update?: string | null; last_full_scan?: string | null; install_date?: string | null; install_id?: number }
export interface Branch { branch: string | null; installs: number; hosts: number; packages_count: number; versions: string[]; packages: { product_id: number; name: string; version: string; publisher: string; platform: string; compared_version: string }[] }
export interface Grouped { rule: { key: string; name: string; name_like: string; name_regex: string; branch_regex: string | null }; branches: Branch[]; products: number; installs: number; hosts: number; fetched_at: string }
export interface ReportParams { product_ids?: number[]; rule?: string | null; branches?: string[]; name_like?: string | null; name_regex?: string | null; min_version?: string | null; max_version?: string | null; below_version?: string | null; platform?: string | null; group_contains?: string | null; active_days?: number | null; include_inactive?: boolean; inactive_only?: boolean; q?: string | null; os_contains?: string | null }
export interface SoftwareRow { name: string; fqdn: string; ip: string; os: string; linux_release: string; platform: string; app_name: string; app_version: string; compared_version: string; branch: string; publisher: string; install_date: string | null; last_connected: string | null; days_since_connection: number | null; activity: string; group: string; host_id: number; product_id: number; install_id: number }
export interface Summary { products: number; installs_total: number; rows: number; hosts: number; excluded_inactive_hosts: number; excluded_not_computers: number; branches?: { branch: string; installs: number; hosts: number; packages: string[] }[]; active_days: number | null; include_inactive: boolean; fetched_at: string }
export interface CatalogState { status: "empty" | "building" | "ready" | "failed"; built_at?: string | null; started_at?: string | null; requested_at?: string | null; activity_days?: number | null; progress?: string | null; error?: string | null; stats?: { hosts: number; hosts_active: number; records: number; installs: number; products: number } | null; duration_ms?: number | null }
export interface CatalogBranch { branch: string; hosts: number }
export interface CatalogItem { key: string; name: string; publisher: string; publisher_key: string; origin: "builtin" | "auto" | "manual"; component: boolean; family_key: string; family_size: number; family_name?: string; platforms: string[]; hosts: number; hosts_all: number; hosts_active: number; hidden_hosts: number; installs: number; versions_count: number; latest_version: string; oldest_version: string; branches: CatalogBranch[]; first_seen: string | null; built_at: string; scheme: string }
export interface CatalogVersion { version: string; branch: string; scheme: string; raw: string[]; names: string[]; platform: string[]; hosts: number; hosts_all: number; installs: number; records: number }
export interface CatalogOverride { id: string; kind: "merge" | "split" | "rename"; from_key: string | null; match_name: string | null; to_key: string; to_name: string | null; to_publisher: string | null; note: string | null; created_by: string | null; created_at: string }
export interface CatalogProductFull extends Omit<CatalogItem, "branches"> { note: string | null; names: [string, number][]; transform: string | null; versions: CatalogVersion[]; branches: { branch: string; hosts: number; hosts_active: number; hosts_shown: number; installs: number; versions: string[] }[]; builtin: boolean; overrides: CatalogOverride[]; state: CatalogState }
export interface ProductHost { host_id: number; name: string; fqdn: string; ip: string; os: string; group: string; last_connected: string | null; days_since_connection: number | null; activity: string; linux_release: string; versions: { app_name: string; app_version: string; compared_version: string; branch: string }[] }
export type VersionOp = "lt" | "le" | "eq" | "ge" | "gt" | "range" | "any";
export interface AuditItem { kind?: "product" | "pattern" | "rule"; product_key?: string | null; product_keys?: string[]; product_name?: string | null; op: VersionOp; value?: string | null; min?: string | null; max?: string | null; exclude?: string[]; branches?: string[]; target_version?: string | null; platform?: string | null; name_like?: string | null; name_regex?: string | null; publisher_like?: string | null; rule?: string | null }
export interface AuditParams { items: AuditItem[]; active_days?: number | null; include_inactive?: boolean; online_only?: boolean; group_contains?: string | null }
export interface AuditResultRow { source: string; program: string; product?: string; item: number; app_name: string; app_version: string; compared_version: string; branch: string; condition: string; target_version: string; publisher: string; install_date: string | null; name: string; fqdn: string; ip: string; os: string; linux_release: string; group: string; last_connected: string | null; days_since_connection: number | null; activity: string; host_id: number; product_id: number }
export interface AuditSourceSummary { source: string; rows: number; hosts: number; hidden_inactive_hosts: number; excluded_not_computers: number; items: { program: string; condition: string; target_version: string; hosts: number; installs: number; records_checked: number; records_matched: number; versions: [string, number][] }[]; fetched_at: string }
export interface AuditFound { name: string; version: string; compared_version: string; publisher: string; matched: boolean; product: string }
export interface AuditSummary { rows: number; hosts: number; sources: AuditSourceSummary[]; programs: { program: string; condition: string; target_version: string; hosts: number; installs: number; by_source: { source: string; hosts: number }[]; found?: AuditFound[]; explain?: string }[]; hidden_inactive_hosts: number; hidden_offline_hosts?: number; online_only?: boolean; online_unavailable?: boolean; active_days: number | null; include_inactive: boolean; fetched_at: string; notes?: string[]; errors?: { source: string; message: string }[] }
export interface SavedCheck { id: string; kind: "version_audit" | "legacy"; name: string; description: string | null; params: AuditParams | null; selection: ReportParams | null; source_ids: string[]; source_names: string[]; shared: boolean; owner_id: string | null; created_by: string | null; created_at: string; updated_at: string | null; last_run_at: string | null; last_job_id: string | null; cve: string | null; severity: string }
export interface VulnHost { host_id: number; name: string; fqdn: string; ip: string; os: string; os_version: string; group: string; last_connected: string | null; days_since_connection: number | null; activity: string; critical: number; high: number; warning: number; total: number; patchable: number; products: number; last_detected: string | null }
export interface VulnSummary { hosts: number; hidden_hosts: number; total: number; critical_hosts: number; high_hosts: number; warning_hosts: number; critical: number; high: number; warning: number; patchable: number; activity_days: number; fetched_at: string }
export interface VulnProduct { product_id: number | null; name: string; hosts: number; vulns: number; critical: number; high: number; warning: number; total: number; patchable: number; last_detected: string | null }
export interface HostVuln { occurrence_id: number; kla_id: string; severity: "critical" | "high" | "warning"; severity_label: string; url: string; product: string; product_version: string; app_name: string; app_version: string; publisher: string; detected: string | null; patches_available: boolean; cve: string[]; mssb: string[]; kb: string[] }
export type ProblemKey = "no_av" | "rtp_off" | "infected" | "bases_old" | "license" | "scan_old" | "reboot";
export interface ProtHost { host_id: number; name: string; fqdn: string; ip: string; os: string; platform: string; group: string; last_connected: string | null; days_since_connection: number | null; activity: string; last_full_scan: string | null; online: boolean | null; last_visible: string | null; last_info_update: string | null;
  av: { code: string; product: string; build: string; state: number | null; state_label: string; bases: string | null; has_rtp: boolean } | null; agent_build: string; rtp_state: number | null; rtp_label: string; ksc_status: string | null; uncured: number; problems: ProblemKey[] }
export interface ProtVersions { code: string; product: string; hosts: number; latest: string; on_latest: number; versions: { build: string; hosts: number }[] }
export interface ProtSummary { hosts: number; hidden_hosts: number; offline_hosts: number; online_only: boolean; online_data: boolean; activity_days: number; bases_days: number; scan_days: number; ok: number; protected: number; problems: { key: ProblemKey; title: string; hint: string; hosts: number }[];
  ksc_status: Record<string, number>; reasons: { bit: number; title: string; hosts: number }[]; versions: ProtVersions[]; fetched_at: string }
export type EvGroup = "detections" | "notcured" | "resolved" | "attacks";
export interface EvSummary { days: number; unit: "hour" | "day"; types: { key: string; title: string; group: EvGroup; n: number; hosts: number }[]; totals: Record<EvGroup, number>; hosts: Record<EvGroup | "any_hosts", number>;
  trend: ({ at: string } & Record<EvGroup, number>)[]; top_hosts: { host_id: number | null; name: string; ip: string; deleted: boolean; n: number; detections: number; notcured: number; attacks: number; last: string | null }[];
  top_threats: { kind: "threat" | "attack"; name: string; n: number; hosts: number; last: string | null }[]; fetched_at: string; unsupported?: string[] }
export interface SecEvent { event_id: number; at: string | null; type: string; type_title: string; severity: number | null; host_id: number | null; host: string; ip: string; product: string; threat: string; object: string; user: string; threat_kind: string; attacker: string; protocol: string; port: string }
export interface Job { id: string; source_id: string | null; source_ids: string[]; source_name: string; kind: "software_hosts" | "hosts" | "version_audit"; title: string; params: ReportParams & Partial<AuditParams>; status: "queued" | "running" | "done" | "failed" | "cancelled"; progress: string | null; created_by: string; created_at: string; started_at: string | null; finished_at: string | null; data_fetched_at: string | null; rows: number | null; summary: (Summary & Partial<AuditSummary>) | null; error: string | null }
export interface Template { id: string; name: string; kind: Job["kind"]; params: ReportParams & Partial<AuditParams>; shared: boolean; owner_id: string | null; created_at: string }
export interface AdminUser { id: string; username: string; display_name: string; email: string | null; auth_source: string; role: User["role"]; is_active: boolean; all_sources: boolean; source_ids: string[]; must_change_password: boolean; last_login_at: string | null; created_at: string; totp_enabled?: boolean; totp_enabled_at?: string | null }
export interface Rule { id?: string; key: string; name: string; name_like: string; name_regex: string; branch_regex: string | null; branch_parts: number; exclude_regex: string | null; description: string | null; builtin?: boolean; enabled: boolean }
export interface Dashboard { source: SourceRef; summary: { activity_days: number; hosts_total?: number; hosts_active?: number; hosts_inactive?: number; products?: number; installs?: number; ksc_version?: string | null; fetched_at: string; hosts_error?: string; software_error?: string } | null; error: string | null; reports_total: number; recent_reports: { id: string; title: string; status: string; created_at: string; rows: number | null }[] }
export interface SystemStatus { version: string; commit: string; built_at: string; public_url: string; master_key_ok: boolean; uptime_s: number; checks: Record<string, { ok: boolean; error?: string | null; running?: number; queued?: number; last_done?: string | null; optional?: boolean; version?: string; size?: number; connections?: number }>;
  components: { key: string; title: string; ok: boolean | null; detail: string | null }[];
  sources: { id: string; name: string; is_active: boolean; last_check_at: string | null; last_check_ok: boolean | null; ksc_version: string | null; catalog_status: string; catalog_built_at: string | null }[]; counts: Record<string, number>; disk_free_bytes: number | null;
  resources: { cpu_count: number | null; load: number[] | null; memory_total?: number; memory_available?: number; disk_data: { total: number; used: number; free: number } | null; disk_root: { total: number; used: number; free: number } | null };
  storage: { database: number | null; reports: number | null; backups: number | null; images: number | null; images_list: { name: string; bytes: number }[]; docker_free: number | null; data_free: number | null; host_checked_at: number | null };
  recent_errors: { at: string; category: string; event: string; source: string | null; message: string | null }[]; recent_checks: { at: string; level: string; event: string; source: string | null; message: string | null }[];
  update_history: { at: number; action: string; result: string; from_version: string; to_version: string; by: string; stage?: string }[]; security: { https: boolean; secure_cookie: boolean; cookie_mode: string; totp_policy: string } }
export interface AuditRow { id: number; at: string; actor: string; action: string; target_type: string; target_id: string; source_id: string | null; details: unknown; result: string; ip: string | null; duration_ms: number | null }
export interface JournalRow { id: number; at: string; level: string; category: string; event: string; user: string | null; source: string | null; message: string | null; data: unknown; duration_ms: number | null; ip: string | null; request_id: string | null }
export interface UpdatesOverview { installed: { version: string; commit: string; built_at: string }; updater: { available: boolean; heartbeat_age_s: number | null; state: string; action: string; step_no: number; step_total: number; step_name: string; started_at: number; finished_at: number; exit_code: number | null; result: string; request_pending: boolean; by: string; target: string }; remote: { checked_at: number; ok: boolean; error: string; current_version: string; latest_version: string; latest_tag: string; behind: boolean; notes: string; published_at: string; age_s: number } | null; history: { at: number; action: string; result: string; from_version: string; to_version: string; by: string; stage?: string }[]; backups: { name: string; size: number; at: number }[]; can_act: boolean; reasons: string[]; commands: Record<string, string>;
  preflight: { checked_at: number; age_s: number; target: string; ok: boolean; items: { key: string; status: "ok" | "warn" | "fail"; message: string }[] } | null;
  report: { finished_at: number; result: "ok" | "failed"; stage: string; from_version: string; to_version: string; advice: string; actions: string[] } | null }
export type SettingsValues = Record<string, string | number | boolean | null>;
export interface TotpStatus { available: boolean; policy: string; enabled: boolean; required: boolean; backup_left: number; enabled_at: string | null }
export interface LdapConn { id: string; name: string; enabled: boolean; is_primary: boolean; protocol: "ldaps" | "starttls"; host: string; port: number; url: string; ldap_version: number; timeout_s: number; base_dn: string; domain_dns: string; netbios: string; bind_dn: string; bind_password_set: boolean; login_attribute: string; display_name_attribute: string; email_attribute: string; user_filter: string; nested_groups: boolean; position: number; last_check_at: string | null; last_check_ok: boolean | null; created_at: string; updated_at: string | null }
export interface CaCert { id: string; label: string; subject: string; issuer: string; serial: string; sha256: string; not_before: string; not_after: string; is_ca: boolean; self_signed: boolean; type: string; expired: boolean; expires_soon: boolean; added_by: string | null; created_at: string }
export interface CertPreview { subject: string; issuer: string; serial: string; sha256: string; not_before: string; not_after: string; is_ca: boolean; self_signed: boolean; expired: boolean; not_yet_valid: boolean; type: string }
export interface AccessRuleT { id: string; connection_id: string | null; connection: string; group_dn: string; role: User["role"]; all_sources: boolean; source_ids: string[]; note: string | null; created_at: string }
export interface LdapDiag extends DiagResult { server_certificate?: { subject: string; issuer: string; not_after: string; san: string[] }; test_user?: { display_name: string; username: string; email?: string | null; groups: string[]; role: string | null; sources?: string; rules?: string[]; disabled?: boolean } }

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
  login: (login: string, password: string, domain = "") => req<Me | { totp_required: true; challenge: string }>("POST", "/auth/login", { login, password, domain }),
  loginOptions: () => req<{ domains: { id: string; name: string }[] }>("GET", "/auth/login-options"),
  loginTotp: (challenge: string, code: string) => req<Me>("POST", "/auth/login/totp", { challenge, code }),
  totp: {
    status: () => req<TotpStatus>("GET", "/auth/totp/status"),
    setup: (password: string) => req<{ secret: string; uri: string; qr_svg: string; expires_in: number }>("POST", "/auth/totp/setup", { password }),
    enable: (code: string) => req<{ backup_codes: string[] }>("POST", "/auth/totp/enable", { code }),
    disable: (password: string, code: string) => req<void>("POST", "/auth/totp/disable", { password, code }),
    backupCodes: (password: string, code: string) => req<{ backup_codes: string[] }>("POST", "/auth/totp/backup-codes", { password, code }),
  },
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
  catalog: {
    list: (p: Record<string, string | number | boolean | undefined>) => req<Page<CatalogItem> & { state: CatalogState }>("GET", `/catalog${qs(p)}`),
    publishers: (p: Record<string, string | number | boolean | undefined>) => req<Page<{ publisher_key: string; publisher: string; products: number; max_hosts: number; top: string[] }>>("GET", `/catalog/publishers${qs(p)}`),
    state: () => req<CatalogState>("GET", "/catalog/state"),
    rebuild: () => req<CatalogState>("POST", "/catalog/rebuild"),
    search: (q: string, sourceIds: string[]) => req<{ items: { key: string; name: string; publisher: string; hosts: number; hosts_all: number; latest_version: string; component: boolean }[] }>("GET", `/catalog/search${qs({ q, source_ids: sourceIds.join(",") })}`),
    product: (key: string, allHosts = false) => req<CatalogProductFull>("GET", `/catalog/products/${encodeURIComponent(key)}${qs({ all_hosts: allHosts })}`),
    productHosts: (key: string, p: { version?: string; branch?: string | null; all_hosts?: boolean; offset?: number; limit?: number }) => req<Page<ProductHost> & { hidden_hosts: number; fetched_at: string }>("GET", `/catalog/products/${encodeURIComponent(key)}/hosts${qs(p)}`),
    overrides: () => req<{ items: CatalogOverride[] }>("GET", "/catalog/overrides"),
    addOverride: (body: { kind: CatalogOverride["kind"]; from_key?: string | null; match_names?: string[]; to_key?: string | null; to_name?: string | null; to_publisher?: string | null; note?: string | null }) => req<{ items: CatalogOverride[] }>("POST", "/catalog/overrides", body),
    deleteOverride: (id: string) => req<void>("DELETE", `/catalog/overrides/${id}`),
  },
  audit: {
    preview: (params: AuditParams, sourceIds: string[], limit = 300) => req<{ summary: AuditSummary; items: AuditResultRow[]; total: number }>("POST", "/audit/preview", { params, source_ids: sourceIds, limit }),
  },
  checks: {
    list: () => req<{ items: SavedCheck[] }>("GET", "/checks"),
    create: (body: { name: string; description?: string | null; params: AuditParams; source_ids: string[]; shared?: boolean }) => req<SavedCheck>("POST", "/checks", body),
    update: (id: string, body: { name: string; description?: string | null; params: AuditParams; source_ids: string[]; shared?: boolean }) => req<SavedCheck>("PUT", `/checks/${id}`, body),
    remove: (id: string) => req<void>("DELETE", `/checks/${id}`),
    run: (id: string) => req<Job>("POST", `/checks/${id}/run`),
  },
  vulns: {
    hosts: (p: Record<string, string | number | boolean | undefined | null>) => req<Page<VulnHost> & { summary: VulnSummary | null; unsupported?: string[] }>("GET", `/vulnerabilities/hosts${qs(p)}`),
    products: (p: Record<string, string | number | boolean | undefined | null>) => req<Page<VulnProduct> & { fetched_at?: string; activity_days?: number; unsupported?: string[] }>("GET", `/vulnerabilities/products${qs(p)}`),
    host: (id: number) => req<{ host: Host; items: HostVuln[]; counts: Record<"critical" | "high" | "warning", number>; total: number; fetched_at: string; unsupported?: string[] }>("GET", `/vulnerabilities/hosts/${id}`),
  },
  protection: (p: Record<string, string | number | boolean | undefined | null>) => req<Page<ProtHost> & { summary: ProtSummary | null; unsupported?: string[] }>("GET", `/protection${qs(p)}`),
  events: {
    summary: (days: number, refresh?: boolean) => req<EvSummary>("GET", `/events/summary${qs({ days, refresh })}`),
    list: (p: Record<string, string | number | boolean | undefined | null>) => req<Page<SecEvent> & { days?: number; unsupported?: string[] }>("GET", `/events${qs(p)}`),
  },
  hosts: {
    list: (p: Record<string, string | number | boolean | undefined>) => req<Page<Host> & { hidden: number; activity_days: number; fetched_at: string }>("GET", `/hosts${qs(p)}`),
    one: (id: number) => req<{ host: Host; activity_days: number; fetched_at: string; software: { install_id: number; product_id: number; name: string; version: string; publisher: string; install_date: string | null }[]; kaspersky: { product_code: string; product: string; build: string; state: string; av_bases_date: string | null; is_av: boolean; has_rtp: boolean }[] }>("GET", `/hosts/${id}`),
  },
  reports: {
    list: (sourceOnly = true) => req<{ items: Job[] }>("GET", `/reports${qs({ source_only: sourceOnly })}`),
    create: (kind: Job["kind"], title: string, params: ReportParams | AuditParams, sourceIds: string[] = []) => req<Job>("POST", "/reports", { kind, title, params, source_ids: sourceIds }),
    get: (id: string) => req<Job>("GET", `/reports/${id}`),
    rows: (id: string, p: { offset: number; limit: number; q?: string; source?: string; program?: string; sort?: string; desc?: boolean }) => req<Page<SoftwareRow & Host & AuditResultRow>>("GET", `/reports/${id}/rows${qs(p)}`),
    downloadUrl: (id: string, fmt: "csv" | "xlsx") => `/api/v1/reports/${id}/download/${fmt}`,
    cancel: (id: string) => req<Job>("POST", `/reports/${id}/cancel`),
    rerun: (id: string) => req<Job>("POST", `/reports/${id}/rerun`),
    remove: (id: string) => req<void>("DELETE", `/reports/${id}`),
    templates: () => req<{ items: Template[] }>("GET", "/report-templates"),
    saveTemplate: (name: string, kind: Job["kind"], params: ReportParams | AuditParams, shared = true) => req<Template>("POST", "/report-templates", { name, kind, params, shared }),
    deleteTemplate: (id: string) => req<void>("DELETE", `/report-templates/${id}`),
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
    ldap: {
      connections: () => req<{ items: LdapConn[] }>("GET", "/admin/ldap/connections"),
      create: (body: Partial<LdapConn> & { url?: string; bind_password?: string }) => req<LdapConn>("POST", "/admin/ldap/connections", body),
      update: (id: string, body: Partial<LdapConn> & { url?: string; bind_password?: string | null }) => req<LdapConn>("PUT", `/admin/ldap/connections/${id}`, body),
      remove: (id: string) => req<void>("DELETE", `/admin/ldap/connections/${id}`),
      removeSecret: (id: string) => req<LdapConn>("DELETE", `/admin/ldap/connections/${id}/secret`),
      test: (id: string, test_login = "", test_password = "") => req<LdapDiag>("POST", `/admin/ldap/connections/${id}/test`, { test_login, test_password }),
      groups: (q: string) => req<{ items: { dn: string; name: string; description: string; connection: string }[]; errors: string[] }>("GET", `/admin/ldap/groups${qs({ q })}`),
      certs: () => req<{ items: CaCert[] }>("GET", "/admin/ldap/certs"),
      previewCert: (body: { pem?: string; data_base64?: string }) => req<{ new: CertPreview[]; existing: CertPreview[] }>("POST", "/admin/ldap/certs/preview", body),
      addCert: (body: { pem?: string; data_base64?: string; label?: string; confirm_non_ca?: boolean }) => req<{ added: CertPreview[]; existing: CertPreview[] }>("POST", "/admin/ldap/certs", body),
      deleteCert: (id: string) => req<void>("DELETE", `/admin/ldap/certs/${id}`),
      rules: () => req<{ items: AccessRuleT[] }>("GET", "/admin/ldap/rules"),
      createRule: (body: { connection_id: string | null; group_dn: string; role: string; all_sources: boolean; source_ids: string[]; note?: string | null }) => req<AccessRuleT>("POST", "/admin/ldap/rules", body),
      updateRule: (id: string, body: { connection_id: string | null; group_dn: string; role: string; all_sources: boolean; source_ids: string[]; note?: string | null }) => req<AccessRuleT>("PUT", `/admin/ldap/rules/${id}`, body),
      deleteRule: (id: string) => req<void>("DELETE", `/admin/ldap/rules/${id}`),
      checkUser: (login: string, password = "", domain = "") => req<DiagResult & { found: boolean; message?: string; display_name?: string; username?: string; email?: string | null; connection?: string; disabled?: boolean; groups?: string[]; role?: string | null; all_sources?: boolean; sources?: string[]; rules?: string[] }>("POST", "/admin/ldap/check-user", { login, password, domain }),
    },
    resetTotp: (userId: string, password: string) => req<void>("POST", `/admin/users/${userId}/totp/reset`, { password }),
    catalog: () => req<{ items: (CatalogState & { source_id: string; source: string; is_active: boolean })[] }>("GET", "/admin/catalog"),
    catalogRebuild: (sourceId: string) => req<CatalogState>("POST", `/admin/catalog/${sourceId}/rebuild`),
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
    updatesPreflight: () => req<{ request_id: string }>("POST", "/admin/updates/preflight"),
    updatesRestore: (name: string, confirm: string) => req<{ request_id: string }>("POST", "/admin/updates/restore", { name, confirm }),
    updatesLog: (offset: number) => req<{ offset: number; size: number; text: string; reset: boolean; state: string; step_no: number; step_total: number; step_name: string; result: string; exit_code: number | null; finished_at: number }>("GET", `/admin/updates/log${qs({ offset })}`),
  },
};
