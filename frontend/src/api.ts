// Клиент REST API. Сессия — HttpOnly cookie; CSRF-токен хранится только в памяти; выбранный источник — в сессии (и дублируется заголовком).
export interface User { id: string; username: string; display_name: string; role: "admin" | "analyst" | "viewer"; is_admin: boolean; local: boolean }
export interface Me { user: User; csrf_token: string; must_change_password: boolean; current_source_id: string | null; site_name: string; activity_days: number; must_enroll_totp: boolean; totp_enabled: boolean; second_factor: string | null; secure_cookie: boolean }
export interface SourceRef { id: string; name: string; host: string; port: number; database: string; is_active: boolean; last_check_at: string | null; last_check_ok: boolean | null; ksc_version: string | null; features: Record<string, boolean | null> }
export interface Stage { stage: string; ok: boolean | null; message: string; ms: number }
export interface DiagResult { ok: boolean; stages: Stage[]; server?: { version: string; edition: string; database: string }; features?: Record<string, { ok: boolean; title: string; missing: string[] }>; warnings?: string[]; ksc_version?: string | null; hosts?: number; test_user?: { display_name: string; username: string; role: string | null; groups: string[] } }
export interface SourceFull extends SourceRef { auth_type: string; username: string; password_set: boolean; tls_mode: string; trust_server_cert: boolean; connect_timeout_s: number; query_timeout_s: number; last_check: DiagResult | null; created_at: string }
export interface Product { product_id: number; name: string; version: string; publisher: string; platform: string; first_seen: string | null; upstream_version: string; installs: number; hosts: number }
export interface Page<T> { items: T[]; total: number; offset: number; limit: number }
export interface Host { zone?: string; host_id: number; name: string; fqdn: string; ip: string; os: string; os_version: string; platform: string; group: string; last_connected: string | null; last_visible: string | null; online?: boolean | null; days_since_connection: number | null; activity: string; linux_release: string; rtp_state_label?: string; ksc_status?: { status: string; reasons: string[] } | null; protection?: { problems: ProblemKey[]; bases_days: number; scan_days: number } | null; last_av_update?: string | null; last_full_scan?: string | null; install_date?: string | null; install_id?: number }
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
export interface AuditParams { items: AuditItem[]; active_days?: number | null; include_inactive?: boolean; online_only?: boolean; group_contains?: string | null; zone?: string | null }
export interface AuditResultRow { source: string; program: string; product?: string; item: number; app_name: string; app_version: string; compared_version: string; branch: string; condition: string; target_version: string; publisher: string; install_date: string | null; name: string; fqdn: string; ip: string; os: string; linux_release: string; group: string; last_connected: string | null; days_since_connection: number | null; activity: string; host_id: number; product_id: number }
export interface AuditSourceSummary { source: string; rows: number; hosts: number; hidden_inactive_hosts: number; excluded_not_computers: number; items: { program: string; condition: string; target_version: string; hosts: number; installs: number; records_checked: number; records_matched: number; versions: [string, number][] }[]; fetched_at: string }
export interface AuditFound { name: string; version: string; compared_version: string; publisher: string; matched: boolean; product: string }
export interface AuditSummary { rows: number; hosts: number; sources: AuditSourceSummary[]; programs: { program: string; condition: string; target_version: string; hosts: number; installs: number; by_source: { source: string; hosts: number }[]; found?: AuditFound[]; explain?: string }[]; hidden_inactive_hosts: number; hidden_offline_hosts?: number; online_only?: boolean; online_unavailable?: boolean; active_days: number | null; include_inactive: boolean; fetched_at: string; notes?: string[]; errors?: { source: string; message: string }[] }
export interface SavedCheck { id: string; kind: "version_audit" | "legacy"; name: string; description: string | null; params: AuditParams | null; selection: ReportParams | null; source_ids: string[]; source_names: string[]; shared: boolean; owner_id: string | null; created_by: string | null; created_at: string; updated_at: string | null; last_run_at: string | null; last_job_id: string | null; cve: string | null; severity: string }
export interface VulnHost { zone?: string; host_id: number; name: string; fqdn: string; ip: string; os: string; os_version: string; group: string; last_connected: string | null; days_since_connection: number | null; activity: string; critical: number; high: number; warning: number; total: number; patchable: number; products: number; last_detected: string | null }
export interface VulnSummary { hosts: number; hidden_hosts: number; total: number; critical_hosts: number; high_hosts: number; warning_hosts: number; critical: number; high: number; warning: number; patchable: number; activity_days: number; fetched_at: string }
export interface VulnProduct { product_id: number | null; name: string; hosts: number; vulns: number; critical: number; high: number; warning: number; total: number; patchable: number; last_detected: string | null }
export interface HostVuln { occurrence_id: number; kla_id: string; severity: "critical" | "high" | "warning"; severity_label: string; url: string; product: string; product_version: string; app_name: string; app_version: string; publisher: string; detected: string | null; patches_available: boolean; cve: string[]; mssb: string[]; kb: string[] }
export type ProblemKey = "no_av" | "rtp_off" | "infected" | "bases_old" | "license" | "scan_old" | "reboot";
export interface ProtHost { zone?: string; host_id: number; name: string; fqdn: string; ip: string; os: string; platform: string; group: string; last_connected: string | null; days_since_connection: number | null; activity: string; last_full_scan: string | null; online: boolean | null; last_visible: string | null; last_info_update: string | null;
  av: { code: string; product: string; build: string; state: number | null; state_label: string; bases: string | null; has_rtp: boolean } | null; agent_build: string; rtp_state: number | null; rtp_label: string; ksc_status: string | null; uncured: number; problems: ProblemKey[] }
export interface ProtVersions { code: string; product: string; hosts: number; latest: string; on_latest: number; versions: { build: string; hosts: number }[] }
export interface ProtSummary { hosts: number; hidden_hosts: number; offline_hosts: number; online_only: boolean; online_data: boolean; activity_days: number; bases_days: number; scan_days: number; ok: number; protected: number; problems: { key: ProblemKey; title: string; hint: string; hosts: number }[];
  ksc_status: Record<string, number>; reasons: { bit: number; title: string; hosts: number }[]; versions: ProtVersions[]; fetched_at: string }
export type EvGroup = "detections" | "notcured" | "resolved" | "attacks";
export interface EvSummary { days: number; unit: "hour" | "day"; types: { key: string; title: string; group: EvGroup; n: number; hosts: number }[]; totals: Record<EvGroup, number>; hosts: Record<EvGroup | "any_hosts", number>;
  trend: ({ at: string } & Record<EvGroup, number>)[]; top_hosts: { host_id: number | null; name: string; ip: string; deleted: boolean; n: number; detections: number; notcured: number; attacks: number; last: string | null }[];
  top_threats: { kind: "threat" | "attack"; name: string; n: number; hosts: number; last: string | null }[]; fetched_at: string; unsupported?: string[] }
export interface SecEvent { host_known: boolean; event_id: number; at: string | null; type: string; type_title: string; severity: number | null; host_id: number | null; host: string; ip: string; product: string; threat: string; object: string; user: string; threat_kind: string; attacker: string; protocol: string; port: string }
export interface Job { id: string; source_id: string | null; source_ids: string[]; source_name: string; kind: "software_hosts" | "hosts" | "version_audit" | QuickKind; title: string; params: ReportParams & Partial<AuditParams> & Record<string, unknown>; status: "queued" | "running" | "done" | "failed" | "cancelled"; progress: string | null; created_by: string; created_at: string; started_at: string | null; finished_at: string | null; data_fetched_at: string | null; rows: number | null; summary: (Summary & Partial<AuditSummary> & Partial<QuickDoc>) | null; error: string | null }
export type QuickKind = "quick_zone" | "quick_vulns" | "quick_hosts" | "quick_protection" | "quick_events" | "quick_extvulns" | "quick_eol";
export interface QuickCol { key: string; title: string; type: string }
export interface QuickMetric { key: string; label: string; value: number | string; hint: string; tone: string }
/** Документ быстрого отчёта без строк: один источник правды для просмотра, XLSX, HTML и CSV. */
export interface QuickDoc { kind?: string; title: string; subtitle: string; conditions: { label: string; text: string }[]; metrics: QuickMetric[]; notes: string[]; generated_at?: string; source?: string;
  severity: { title: string; levels: { key: string; label: string; value: number; hint: string }[] } | null; tables: { id: string; title: string; columns: QuickCol[]; n: number; note: string }[] }
export interface QuickPreview { doc: QuickDoc | null; items: Record<string, string | number | null>[]; total: number; columns: QuickCol[]; fetched_at?: string; preview_rows?: number; html_row_limit?: number; unsupported?: string[] }
export interface VulnDescr { descr_id: number; kla_id: string; severity: "critical" | "high" | "warning"; severity_label?: string; cve: string[]; kb: string[]; products: string[]; hosts: number; total: number; patchable: number; last_detected: string | null; url?: string }
export interface VulnListSummary { vulns: number; critical: number; high: number; warning: number; patchable: number; activity_days: number; fetched_at: string }
export type VdbStatus = "confirmed" | "potential" | "clarify" | "fixed" | "insufficient";
export interface VdbFinding { status: VdbStatus; status_ru: string; installs: number; hosts_max: number; new: boolean; first_seen_at: string | null; products: { key: string; name: string; versions: string[]; installs: number; hosts: number }[] }
/** Одна оценка CVSS: версия методики, балл 0.0–10.0, вектор, уровень, кто выставил (origin_label), источник данных, ссылка на первоисточник и дата обновления записи. */
export interface VdbScore { version: string; score: number; vector: string; severity: string; severity_ru: string; source: string; source_title: string; origin: string; origin_label: string; kind: string;
  updated: string | null; url: string; primary?: boolean }
export interface VdbVulnRow { key: string; title: string; severity: string; severity_ru: string; severity_basis: "cvss" | "source" | ""; sev_rank: number; score: number | null; score_version: string; score_source: string; exploited: boolean; has_fix: boolean | null; published: string | null; modified: string | null;
  sources: string[]; ids: string[]; products: string[]; description: string; finding?: VdbFinding; version_match?: "yes" | "unknown" }
export interface VdbRunRow { started_at: string | null; finished_at: string | null; trigger: string; status: string; fetched: number; changed: number; duration_ms: number | null; error: string | null; channel: string; attempts: VdbAttempt[] }
export interface VdbAttempt { channel: string; title: string; ok: boolean; error: string; ms: number; records: number }
export interface VdbSourceInfo { channel: string; channels: string[]; attempts: VdbAttempt[]; key: string; title: string; url: string; terms: string; mode: "full" | "incremental"; enabled: boolean; interval_hours: number; settings: Record<string, unknown>; secret_set: boolean;
  status: "never" | "running" | "ok" | "error"; progress: string | null; last_started_at: string | null; last_ok_at: string | null; last_duration_ms: number | null; last_error: string | null; records: number;
  requested: boolean; can_restore: boolean; upload: boolean; runs: VdbRunRow[] }
export interface VdbAffectedRow { vendor: string; product: string; ecosystem: string; cpe: string; purl: string; platform: string; exact: string; from: string; from_incl: boolean; to: string; to_incl: boolean; fixed: string;
  all_versions: boolean; version_text: string; conditional: boolean }
export interface VdbRecordOut { source: string; scores: VdbScore[]; title: string; ext_id: string; aliases: string[]; severity: string; severity_ru: string; score: number | null; vector: string; published: string | null; modified: string | null;
  exploited: boolean; fix_available: boolean | null; fix_text: string; status: string; title_text: string; description: string; refs: { url: string; tags: string[] }[]; extra: Record<string, unknown>;
  affected: VdbAffectedRow[]; affected_total: number }
export interface VdbMatchOut { product_key: string; product: string; version: string; status: VdbStatus; status_ru: string; basis: string; confidence: string; hosts: number; installs: number; claims: { source: string; status_ru: string; basis: string }[] }
export interface VdbCard extends VdbVulnRow { cvss: { primary: VdbScore; all: VdbScore[] } | null; records: VdbRecordOut[]; differences: { field: string; values: Record<string, string | number> }[]; infrastructure: { catalog: boolean; matches: VdbMatchOut[] } | null }
export interface VdbMapping { id: string; vendor_key: string; product_key: string; catalog_key: string; action: "map" | "exclude"; note: string | null; created_by: string | null; created_at: string }
export interface VdbCounts { total: number; new: number; new_exploited: number; new_critical: number; new_serious: number }
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
export interface UpdatesOverview { installed: { version: string; commit: string; built_at: string }; updater: { available: boolean; heartbeat_age_s: number | null; state: string; action: string; step_no: number; step_total: number; step_name: string; started_at: number; finished_at: number; exit_code: number | null; result: string; request_pending: boolean; by: string; target: string; last_output_at: number; stalled_s: number | null; interrupted: boolean; api_outdated: boolean; updater_api: number; api_expected: number; now: number; mode: string; op_id: string; phase: string; down_reason: string; boot_changed: boolean; helper_pid: number | null; operation_alive: boolean | null; starts_10m?: number | null; script_sha?: string };
  doctor: { checked_at: number; age_s: number; ok: boolean; items: { key: string; ok: boolean; message: string }[] } | null;
  system: { update_mode: string | null; registry: string | null; allow_build: boolean | null; npm_mirror: boolean | null; pip_mirror: boolean | null; helper_unit: string | null }; remote: { checked_at: number; ok: boolean; error: string; current_version: string; latest_version: string; latest_tag: string; behind: boolean; notes: string; published_at: string; age_s: number } | null; history: { at: number; action: string; result: string; from_version: string; to_version: string; by: string; stage?: string }[]; backups: { name: string; size: number; at: number }[]; can_act: boolean; reasons: string[]; commands: Record<string, string>;
  preflight: { checked_at: number; age_s: number; target: string; ok: boolean; items: { key: string; status: "ok" | "warn" | "fail"; message: string }[] } | null;
  report: { started_at?: number; finished_at: number; result: "ok" | "failed" | "recovered"; stage: string; from_version: string; to_version: string; advice: string; reason_code?: string; mode?: string; actions: string[] } | null }
export type SettingsValues = Record<string, string | number | boolean | null>;
export interface TotpStatus { available: boolean; policy: string; enabled: boolean; required: boolean; backup_left: number; enabled_at: string | null }
export interface LdapConn { id: string; name: string; enabled: boolean; is_primary: boolean; protocol: "ldaps" | "starttls"; host: string; port: number; url: string; ldap_version: number; timeout_s: number; base_dn: string; domain_dns: string; netbios: string; bind_dn: string; bind_password_set: boolean; login_attribute: string; display_name_attribute: string; email_attribute: string; user_filter: string; nested_groups: boolean; position: number; last_check_at: string | null; last_check_ok: boolean | null; created_at: string; updated_at: string | null }
export interface CaCert { id: string; label: string; subject: string; issuer: string; serial: string; sha256: string; not_before: string; not_after: string; is_ca: boolean; self_signed: boolean; type: string; expired: boolean; expires_soon: boolean; added_by: string | null; created_at: string }
export interface CertPreview { subject: string; issuer: string; serial: string; sha256: string; not_before: string; not_after: string; is_ca: boolean; self_signed: boolean; expired: boolean; not_yet_valid: boolean; type: string }
export interface AccessRuleT { id: string; connection_id: string | null; connection: string; group_dn: string; role: User["role"]; all_sources: boolean; source_ids: string[]; note: string | null; created_at: string }
export interface LdapDiag extends DiagResult { server_certificate?: { subject: string; issuer: string; not_after: string; san: string[] }; test_user?: { display_name: string; username: string; email?: string | null; groups: string[]; role: string | null; sources?: string; rules?: string[]; disabled?: boolean } }

// ---- зоны ответственности, рассылки, обработка уязвимостей
export type ZoneRuleKind = "net" | "exclude" | "group" | "name";
export type ContactRole = "responsible" | "cc" | "group";
export interface ZoneRuleT { id?: string; kind: ZoneRuleKind; kind_ru?: string; value: string; note: string }
export interface ZoneContact { id?: string; name: string; position: string; email: string; role: ContactRole; enabled: boolean }
export interface ZoneFull { id: string; name: string; description: string; purpose: string; priority: number; activity_days: number | null; enabled: boolean; updated_at?: string; updated_by?: string | null; rules: ZoneRuleT[]; contacts: ZoneContact[] }
export interface ZoneBrief { id: string; name: string; description: string; purpose: string; priority: number; enabled: boolean; rules: number; contacts: number; updated_at: string }
export type HostState = "critical" | "vulns" | "protection" | "potential" | "ok";
export interface ZoneStats { total: number; in_scope: number; inactive: number; active: number; online: number; offline: number; online_unknown: number; critical: number; other_vulns: number; any_vulns: number; protection: number; potential: number; ok: number;
  state: Record<HostState, number>; severity: { critical: number; high: number; warning: number; none: number }; vulns: { critical: number; high: number; warning: number }; problems: { key: ProblemKey; title: string; hosts: number }[]; excluded: number; accepted: number; review: number }
export interface ZoneCacheSettings { enabled: boolean; at: string; timezone: string; parallel: number; intensity: "low" | "normal" | "high"; max_detections: number; ext_per_host: number; stale_hours: number }
export interface ZoneCacheStatus { settings: ZoneCacheSettings; timezone: string; next_run: string | null; last_success_at: string | null; last_duration_ms: number | null; last_plan: string;
  sources: { id: string; name: string; gen: number; status: string; built_at: string | null; duration_ms: number | null; error: string | null; progress: string | null; hosts: number; detections: number; agg_only: boolean; newer: boolean; probe_at: string | null }[];
  jobs: ZoneJob[]; active: ZoneJob[]; resources: { rss_mb: number; peak_mb: number; soft_mb: number; hard_mb: number; slots: number; used: number; active: string[]; deferred: number } }
export interface ZoneJob { id: string; kind: string; kind_ru: string; zone_id: string | null; trigger: string; status: "queued" | "running" | "done" | "failed"; requested_by: string; requested_at: string; started_at: string | null; finished_at: string | null; progress: string | null; pct: number; attempts: number; error: string | null }
export interface Freshness { empty: boolean; data_at: string | null; calculated_at: string | null; newer: boolean; errors: { source: string; error: string }[]; building: string[]; job: ZoneJob | null; sources: { id: string; name: string; built_at: string | null; status: string; agg_only: boolean }[] }
export interface ZoneEol { hosts: number; eol: number; extended: number; upcoming: number; items: number; os: number }
export interface ZoneOverviewRow { eol: ZoneEol | null; id: string; name: string; description: string; purpose: string; enabled: boolean; stats: Pick<ZoneStats, "total" | "active" | "online" | "critical" | "other_vulns" | "protection" | "ok" | "state" | "inactive">; problem_hosts: number; conflicts: number; responsible: string[]; contacts_n: number; activity_days: number }
export interface ZoneOverview { items: ZoneOverviewRow[]; totals: { zones: number; hosts: number; unique_hosts: number; unassigned: number; conflicts: number }; sources: string[]; activity_days: number; notes: string[]; fetched_at: string | null; freshness: Freshness }
export interface HostCounts { critical: number; high: number; warning: number; total: number; worst: string; accepted: number; excluded: number; review: number }
export interface ZoneHost { source_id: string; source: string; host_id: number; name: string; fqdn: string; ip: string; os: string; group: string; last_connected: string | null; days_since_connection: number | null; active: boolean; online: boolean | null;
  max_sev: "" | "critical" | "high" | "warning"; max_sev_ru: string; max_sev_basis: "" | "ksc" | "ext"; ksc: HostCounts; ext: { total: number; critical: number; high: number; warning: number; kev: number; confirmed: number; accepted: number; excluded: number };
  problems: { key: ProblemKey; title: string }[]; state: HostState; summary: string; zones: string[]; zone_conflict: boolean; zone_pinned: boolean }
export interface ZoneInfo { id: string; name: string; description: string; purpose: string; priority: number; enabled: boolean; activity_days: number | null; contacts: ZoneContact[] }
export interface ZoneDash { zone: ZoneInfo; stats: ZoneStats & { bars: unknown; eol: ZoneEol | null }; activity_days: number; total: number; offset: number; limit: number; items: ZoneHost[]; sources: { id: string; name: string }[]; notes: string[]; fetched_at: string | null; conflicts: number; ext_included: boolean; freshness: Freshness; ext_cap?: number }
export interface TriageDecision { id: string; scope: "host" | "product" | "zone"; scope_ru: string; status: TriageStatus; stored_status: TriageStatus; status_ru: string; stored_status_ru: string; reason: string; reason_ru: string; comment: string; by: string; at: string | null;
  review_until: string | null; recheck: boolean; recheck_reason: string; expired: boolean; version: string; product: string }
export type TriageStatus = "review" | "confirmed" | "false_positive" | "obsolete" | "risk_accepted";
export interface ZoneVulnRow { severity: "critical" | "high" | "warning"; severity_ru: string; kla_id?: string; cve?: string; cve_list?: string[]; vuln_key?: string; ids?: string; title?: string; product?: string; program?: string; installed_version: string; fix?: string; detected?: string | null;
  url?: string; status?: string; status_ru?: string; basis?: string; kev?: boolean; sources?: string; triage: TriageDecision | null; host_id: number; descr_id?: number }
export interface ZoneHostCard extends ZoneHost { zones_info: { id: string; name: string; contacts: ZoneContact[] }[]; candidates: { id: string; name: string }[]; zone_via: string; protection: { key: ProblemKey; title: string; detail: string }[];
  av: { product: string | null; build: string | null; state: string | null; bases: string | null; rtp: string; last_full_scan: string | null; agent: string; ksc_status: string | null };
  rows: { ksc: Record<"current" | "accepted" | "excluded", ZoneVulnRow[]>; ext: Record<"current" | "accepted" | "excluded", ZoneVulnRow[]> } }
export interface TriageRow { id: string; source_id: string; scope: "host" | "product" | "zone"; scope_ru: string; host_id: number | null; host_name: string; zone_id: string | null; vuln_key: string; origin: "ksc" | "ext"; product: string; version: string; status: TriageStatus; stored_status: TriageStatus;
  status_ru: string; stored_status_ru: string; reason: string; reason_ru: string; comment: string; review_until: string | null; recheck: boolean; recheck_reason: string; created_by: string; created_at: string; updated_at: string }
export interface TriageMeta { statuses: { key: TriageStatus; title: string }[]; reasons: { key: string; title: string }[]; scopes: { key: string; title: string }[]; default_review_days: number; can_wide: boolean; can_set: boolean }
export interface TriageBody { source_id: string; vuln_key: string; origin: "ksc" | "ext"; scope: "host" | "product" | "zone"; host_id?: number; host_name?: string; zone_id?: string; product?: string; version?: string; status: TriageStatus; reason?: string; comment?: string; review_until?: string | null }
export interface CsvPlan { mode: string; fingerprint: string; ok: boolean; summary: Record<string, number | string>; zones: { id: string; name: string; action: "create" | "update" | "unchanged" | "skip" | "delete"; rules_add: string[]; rules_remove: string[]; contacts_add: string[]; contacts_update: string[]; contacts_remove: string[]; fields: string[]; lines: number[] }[];
  errors: { line: number; column: string; message: string }[]; warnings: { line: number; column: string; message: string }[]; overlaps: { a: string; b: string; example: string; resolved: boolean }[] }
export interface Conflict { source_id: string; source: string; host_id: number; name: string; ip: string; via: string; conflict: boolean; zones: { id: string; name: string; chosen: boolean }[] }
export interface Composition { total: number; active: number; online: number; shared: number; all_hosts: number; items: { source: string; host_id: number; name: string; ip: string; os: string; group: string; active: boolean; online: boolean | null; also_in: string[]; assigned_here: boolean; via: string }[]; rules: { kind: string; value: string }[] }
export interface Schedule { id: string; name: string; enabled: boolean; zone_ids: string[]; zone_names: string[]; all_zones: boolean; include_unassigned: boolean; sections: string[]; sections_ru: string[]; filters: Record<string, unknown>; level: "management" | "technical"; level_ru: string;
  frequency: "daily" | "weekly" | "monthly"; weekday: number; monthday: number; at_time: string; tz: string; when: string; attach_html: boolean; attach_xlsx: boolean; skip_empty: boolean; next_run_at: string | null; last_run_at: string | null; last_period: string | null; created_by: string | null; created_at: string }
export interface OutboxRow { id: string; schedule_id: string | null; zone_id: string | null; zone_name: string; period_key: string; kind: "schedule" | "manual" | "test"; status: "queued" | "sending" | "accepted" | "failed" | "skipped"; subject: string; to: string[]; cc: string[];
  stats: Record<string, number>; attempts: number; last_error: string | null; refused: { address: string; reply: string }[]; created_at: string; next_attempt_at: string | null; sent_at: string | null }

export type EolStatus = "eol" | "extended" | "upcoming" | "unknown";
export interface EolFinding { source_id: string; source: string; kind: "app" | "os"; kind_ru: string; subject: string; version: string; title: string; publisher: string; eol_product: string; eol_label: string; eol_release: string; status: EolStatus; status_ru: string; severity: "critical" | "high" | "warning" | ""; severity_ru: string; confidence: string; confidence_ru: string; confirmed: boolean; eol_from: string | null; eoas_from: string | null; eoes_from: string | null; days_left: number | null; condition: string; link: string; hosts: number; hosts_active: number; computed_at: string }
export interface EolSourceState { source: string; computed_at: string | null; error: string | null; error_at: string | null; progress: string | null; items: number; ready: boolean }
export interface EolSummary { base: { include_in_analytics: boolean; soon_days: number; products: number; releases: number; enabled: boolean; status: string; last_ok_at: string | null; error: string | null }; all_sources: boolean; findings: Record<"eol" | "extended" | "upcoming", number>; kinds: { app: number; os: number }; devices: { hosts: number; eol: number; extended: number; upcoming: number }; ambiguous: number; sources: Record<string, EolSourceState> }
export type EolInfra = { total: number; by_status: Record<string, number>; items: EolFinding[]; computed_at: string | null; publishers: string[] };
export interface EolProductRow { name: string; label: string; category: string; tags: string[]; releases: number; supported: number; link: string; installed_items: number; installed_hosts: number; updated_at: string }
export interface EolRelease { name: string; label: string; codename: string | null; release_date: string | null; lts: boolean; eoas_from: string | null; eol_from: string | null; eoes_from: string | null; discontinued_from: string | null; latest: string | null; status: string; status_ru: string; severity: string; condition: string; installed_hosts: number; installed_items: number }
export interface EolProductCard { name: string; label: string; category: string; tags: string[]; labels: Record<string, string>; links: Record<string, string>; identifiers: { type: string; id: string }[]; aliases: string[]; releases: EolRelease[]; updated_at: string }
export interface EolHostRow { host_id: number; name: string; ip: string; os: string; last_connected: string | null; active: boolean | null; online: boolean | null; group: string; zones: string[] }
export interface EolMapping { id: string; catalog_key: string; catalog_name: string; eol_product: string | null; eol_label: string; action: "map" | "exclude"; note: string; created_by: string; created_at: string }
export interface DevUser { login: string; domain: string; resolved: boolean; kind: "user" | "service" | "system"; now: boolean; last_session_at: string | null; first_seen_at: string | null; initial: boolean }
export interface DeviceRow { source_id: string; source: string; host_id: number; name: string; ip: string; os: string; group: string; zones: string[]; last_connected: string | null; active: boolean; online: boolean | null; eol: number; eol_level: "" | "eol" | "extended" | "upcoming"; current: DevUser[]; last_user: DevUser | null; week: DevUser[]; week_n: number; history: DevUser[] }
export type DevicesPage = { total: number; items: DeviceRow[]; all_sources: boolean; limits: string; not_ready: string[] };
export interface DevicesStatus { enabled: boolean; interval_minutes: number; hide_service: boolean; limits: string; items: { source_id: string; source: string; supported: boolean; polled_at: string | null; first_poll_at: string | null; rows_seen: number; error: string | null; queued: boolean }[] }
export interface DeviceCard { source_id: string; source: string; host_id: number; name: string; ip: string; os: string; group: string; zones: string[]; last_connected: string | null; active: boolean; online: boolean | null; current: DevUser[]; last_user: DevUser | null; week: DevUser[]; history: DevUser[]; hidden_service: number; eol: EolFinding[]; limits: string }

let csrf = "";
let sourceId: string | null = null;
let allSources = false;
/** Разделы, которые умеют работать со всеми источниками сразу (заголовок X-Source-Id: all); остальные получают выбранный источник. */
const ALL_OK = /^\/(eol|devices|quick\/preview|reports)(\/|\?|$)/;
let onUnauthorized: (() => void) | null = null;
export const setCsrf = (t: string) => { csrf = t; };
export const setSourceId = (id: string | null) => { sourceId = id; };
export const setAllSources = (on: boolean) => { allSources = on; };
const sourceHeader = (path: string) => (allSources && ALL_OK.test(path) ? "all" : sourceId);
export const setUnauthorizedHandler = (fn: (() => void) | null) => { onUnauthorized = fn; };

export class ApiError extends Error {
  constructor(public status: number, message: string, public code = "", public retryAfter?: number) { super(message); }
}

async function req<T>(method: string, path: string, body?: unknown, opts: { raw?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && method !== "HEAD") headers["X-CSRF-Token"] = csrf;
  const sh = sourceHeader(path);
  if (sh) headers["X-Source-Id"] = sh;
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

async function rawPost<T>(path: string, data: ArrayBuffer): Promise<T> {
  const r = await fetch(`/api/v1${path}`, { method: "POST", headers: { "X-CSRF-Token": csrf, "Content-Type": "application/octet-stream", ...(sourceId ? { "X-Source-Id": sourceId } : {}) }, body: data, credentials: "same-origin" });
  if (!r.ok) {
    let msg = `Ошибка ${r.status}`; let detail: unknown = null;
    try { const d = await r.json(); detail = d.detail; if (typeof detail === "string") msg = detail; else if (detail && typeof detail === "object") msg = (detail as { message?: string }).message ?? msg; } catch { /* текст по умолчанию */ }
    const e = new ApiError(r.status, msg); (e as ApiError & { detail?: unknown }).detail = detail; throw e;
  }
  return r.json() as Promise<T>;
}

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
    list: (p: Record<string, string | number | boolean | undefined | null>) => req<Page<VulnDescr> & { summary?: VulnListSummary; unsupported?: string[] }>("GET", `/vulnerabilities/list${qs(p)}`),
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
  eol: {
    summary: (zone = "", sourceId = "") => req<EolSummary>("GET", `/eol/summary${qs({ zone, source_id: sourceId })}`),
    infra: (p: Record<string, string | number | boolean | undefined | null>) => req<EolInfra>("GET", `/eol/infra${qs(p)}`),
    hosts: (p: Record<string, string | number | boolean | undefined | null>) => req<{ total: number; items: EolHostRow[] }>("GET", `/eol/infra/hosts${qs(p)}`),
    products: (p: Record<string, string | number | boolean | undefined | null>) => req<{ total: number; categories: string[]; items: EolProductRow[] }>("GET", `/eol/products${qs(p)}`),
    product: (name: string) => req<EolProductCard>("GET", `/eol/products/${encodeURIComponent(name)}`),
    mappings: () => req<{ items: EolMapping[] }>("GET", "/eol/mappings"),
    setMapping: (b: { catalog_key: string; eol_product?: string | null; action: "map" | "exclude"; note?: string }) => req<{ id: string }>("POST", "/eol/mappings", b),
    delMapping: (id: string) => req<void>("DELETE", `/eol/mappings/${id}`),
    unmatched: (q = "") => req<{ items: { catalog_key: string; name: string; publisher: string; hosts: number; source: string }[]; ambiguous: { catalog_key: string; name: string; publisher: string; hosts: number; reason: string; source: string }[] }>("GET", `/eol/unmatched${qs({ q })}`),
    recalc: () => req<{ queued: number }>("POST", "/eol/recalc"),
    host: (sid: string, hid: number) => req<{ items: EolFinding[] }>("GET", `/eol/hosts/${sid}/${hid}`),
  },
  devices: {
    list: (p: Record<string, string | number | boolean | undefined | null>) => req<DevicesPage>("GET", `/devices${qs(p)}`),
    status: () => req<DevicesStatus>("GET", "/devices/status"),
    poll: () => req<{ queued: number }>("POST", "/devices/poll"),
    card: (sid: string, hid: number, showService = false) => req<DeviceCard>("GET", `/devices/${sid}/${hid}${qs({ show_service: showService })}`),
  },
  vdb: {
    sources: () => req<{ items: VdbSourceInfo[]; vulns: number; ecosystems: string[]; storage: { db_bytes: number | null; tmp_bytes: number; free_bytes: number } }>("GET", "/vdb/sources"),
    syncAll: () => req<{ queued: string[] }>("POST", "/vdb/sync-all"),
    updateSource: (key: string, body: { enabled?: boolean; interval_hours?: number; settings?: Record<string, unknown>; api_key?: string }) => req<VdbSourceInfo>("PUT", `/vdb/sources/${key}`, body),
    sync: (key: string) => req<{ requested: boolean }>("POST", `/vdb/sources/${key}/sync`),
    restore: (key: string) => req<VdbSourceInfo>("POST", `/vdb/sources/${key}/restore`),
    upload: async (file: File) => {
      const r = await fetch("/api/v1/vdb/sources/bdu/upload", { method: "POST", headers: { "X-CSRF-Token": csrf, "Content-Type": "application/octet-stream" }, body: file, credentials: "same-origin" });
      if (!r.ok) { let m = `Ошибка ${r.status}`; try { const d = await r.json(); if (typeof d.detail === "string") m = d.detail; } catch { /* текст по умолчанию */ } throw new ApiError(r.status, m); }
      return r.json() as Promise<{ requested: boolean; bytes: number }>;
    },
    list: (p: Record<string, string | number | boolean | undefined | null>) => req<Page<VdbVulnRow>>("GET", `/vdb/vulns${qs(p)}`),
    card: (key: string) => req<VdbCard>("GET", `/vdb/vulns/${encodeURIComponent(key)}`),
    findings: (p: Record<string, string | number | boolean | undefined | null>) => req<Page<VdbVulnRow> & { summary: VdbCounts }>("GET", `/vdb/findings${qs(p)}`),
    summary: () => req<VdbCounts>("GET", "/vdb/findings/summary"),
    seen: (keys: string[], all = false) => req<VdbCounts>("POST", "/vdb/findings/seen", { keys, all }),
    counts: (keys: string[]) => req<{ items: Record<string, { total: number; kev: number; critical: number; confirmed: number }> }>("GET", `/vdb/catalog-counts${qs({ keys: keys.join(",") })}`),
    product: (key: string) => req<{ items: (VdbVulnRow & { versions: string[] })[]; total: number }>("GET", `/vdb/products/${encodeURIComponent(key).replace(/%2F/g, "/")}`),
    host: (id: number) => req<{ items: { key: string; title: string; severity_ru: string; sev_rank: number; exploited: boolean; product: string; version: string; status: VdbStatus; status_ru: string; basis: string }[]; total?: number; catalog: boolean }>("GET", `/vdb/hosts/${id}`),
    mappings: () => req<{ items: VdbMapping[] }>("GET", "/vdb/mappings"),
    addMapping: (b: { vendor_key?: string; product: string; catalog_key: string; action: "map" | "exclude"; note?: string }) => req<{ id: string }>("POST", "/vdb/mappings", b),
    removeMapping: (id: string) => req<void>("DELETE", `/vdb/mappings/${id}`),
    suggest: (q: string) => req<{ items: { key: string; name: string; publisher: string }[] }>("GET", `/vdb/suggest-products${qs({ q })}`),
  },
  quick: {
    preview: (kind: QuickKind | "version_audit", params: object, refresh = false, sourceIds: string[] = []) => req<QuickPreview>("POST", "/quick/preview", { kind, params, refresh, source_ids: sourceIds }),
  },
  reports: {
    list: (sourceOnly = true) => req<{ items: Job[] }>("GET", `/reports${qs({ source_only: sourceOnly })}`),
    create: (kind: Job["kind"], title: string, params: ReportParams | AuditParams | object, sourceIds: string[] = []) => req<Job>("POST", "/reports", { kind, title, params, source_ids: sourceIds }),
    get: (id: string) => req<Job>("GET", `/reports/${id}`),
    rows: (id: string, p: { offset: number; limit: number; q?: string; source?: string; program?: string; sort?: string; desc?: boolean }) => req<Page<SoftwareRow & Host & AuditResultRow>>("GET", `/reports/${id}/rows${qs(p)}`),
    downloadUrl: (id: string, fmt: "csv" | "xlsx" | "html") => `/api/v1/reports/${id}/download/${fmt}`,
    cancel: (id: string) => req<Job>("POST", `/reports/${id}/cancel`),
    rerun: (id: string) => req<Job>("POST", `/reports/${id}/rerun`),
    remove: (id: string) => req<void>("DELETE", `/reports/${id}`),
    templates: () => req<{ items: Template[] }>("GET", "/report-templates"),
    saveTemplate: (name: string, kind: Job["kind"], params: ReportParams | AuditParams, shared = true) => req<Template>("POST", "/report-templates", { name, kind, params, shared }),
    deleteTemplate: (id: string) => req<void>("DELETE", `/report-templates/${id}`),
  },
  zones: {
    overview: (p: Record<string, string | number | boolean | undefined | null>) => req<ZoneOverview>("GET", `/zones${qs(p)}`),
    options: () => req<{ items: { id: string; name: string }[] }>("GET", "/zones/options/list"),
    dashboard: (id: string, p: Record<string, string | number | boolean | undefined | null>) => req<ZoneDash>("GET", `/zones/${id}${qs(p)}`),
    refresh: (zid: string) => req<{ created: boolean; job: ZoneJob }>("POST", `/zones/${zid}/refresh`),
    refreshState: (zid: string) => req<{ job: ZoneJob | null; last: ZoneJob | null; data_at: string | null; calculated_at: string | null }>("GET", `/zones/${zid}/refresh`),
    host: (zid: string, sourceId: string, hostId: number) => req<ZoneHostCard>("GET", `/zones/${zid}/hosts/${sourceId}/${hostId}`),
    ofHost: (sourceId: string, hostId: number) => req<{ zones: { id: string; name: string; responsible: string[] }[]; candidates: { id: string; name: string }[]; conflict: boolean; pinned?: boolean; via?: string }>("GET", `/zones/of-host/${sourceId}/${hostId}`),
  },
  triage: {
    meta: () => req<TriageMeta>("GET", "/triage/meta"),
    set: (b: TriageBody) => req<TriageRow>("POST", "/triage", b),
    bulk: (items: TriageBody[]) => req<{ count: number }>("POST", "/triage/bulk", { items }),
    list: (p: Record<string, string | number | undefined | null>) => req<Page<TriageRow> & { counts: Record<string, number> }>("GET", `/triage${qs(p)}`),
    history: (id: string) => req<{ decision: TriageRow; events: { at: string; actor: string; action: string; from: string; to: string; comment: string }[] }>("GET", `/triage/${id}/history`),
  },
  admin: {
    zones: {
      list: () => req<{ items: ZoneBrief[] }>("GET", "/admin/zones"),
      cache: () => req<ZoneCacheStatus>("GET", "/admin/zones/cache/status"),
      cacheRun: () => req<{ created: boolean; job: ZoneJob }>("POST", "/admin/zones/cache/run"),
      get: (id: string) => req<ZoneFull>("GET", `/admin/zones/${id}`),
      create: (b: Omit<ZoneFull, "id">) => req<ZoneFull>("POST", "/admin/zones", b),
      update: (id: string, b: Omit<ZoneFull, "id">) => req<ZoneFull>("PUT", `/admin/zones/${id}`, b),
      remove: (id: string) => req<void>("DELETE", `/admin/zones/${id}`),
      composition: (b: { zone_id?: string | null; name: string; priority: number; rules: ZoneRuleT[] }) => req<Composition>("POST", "/admin/zones/preview/composition", b),
      conflicts: () => req<{ items: Conflict[]; total: number; by_via: Record<string, number> }>("GET", "/admin/zones/overview/conflicts"),
      pin: (b: { source_id: string; host_id: number; host_name: string; zone_id: string }) => req<{ ok: boolean }>("POST", "/admin/zones/pins", b),
      unpin: (sourceId: string, hostId: number) => req<void>("DELETE", `/admin/zones/pins/${sourceId}/${hostId}`),
      csvUrl: (what: "sample" | "export") => `/api/v1/admin/zones/csv/${what}`,
      csvPreview: (data: ArrayBuffer, mode: string) => rawPost<CsvPlan>(`/admin/zones/csv/preview${qs({ mode })}`, data),
      csvApply: (data: ArrayBuffer, mode: string, expect: string, confirm: boolean) => rawPost<{ done: Record<string, number>; summary: Record<string, number | string> }>(`/admin/zones/csv/apply${qs({ mode, expect, confirm })}`, data),
    },
    mail: {
      summary: () => req<{ smtp_ready: boolean; smtp_enabled: boolean; counts_30d: Record<string, number>; next_run_at: string | null }>("GET", "/admin/mail/summary"),
      check: () => req<{ ok: boolean; error: string; transient: boolean }>("POST", "/admin/mail/check"),
      test: (to: string) => req<{ ok: boolean; error: string; refused: Record<string, string>; note: string }>("POST", "/admin/mail/test", { to }),
      schedules: () => req<{ items: Schedule[]; categories: { key: string; title: string }[] }>("GET", "/admin/mail/schedules"),
      createSchedule: (b: object) => req<Schedule>("POST", "/admin/mail/schedules", b),
      updateSchedule: (id: string, b: object) => req<Schedule>("PUT", `/admin/mail/schedules/${id}`, b),
      toggleSchedule: (id: string, enabled: boolean) => req<Schedule>("POST", `/admin/mail/schedules/${id}/toggle${qs({ enabled })}`),
      deleteSchedule: (id: string) => req<void>("DELETE", `/admin/mail/schedules/${id}`),
      runSchedule: (id: string, zone_ids: string[] = []) => req<{ queued: number; skipped: number; duplicates: number }>("POST", `/admin/mail/schedules/${id}/run`, { zone_ids }),
      outbox: (p: Record<string, string | number | undefined | null>) => req<{ items: OutboxRow[]; total: number; counts: Record<string, number> }>("GET", `/admin/mail/outbox${qs(p)}`),
      retry: (id: string) => req<OutboxRow>("POST", `/admin/mail/outbox/${id}/retry`),
    },
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
    updatesRun: (target = "", build = false) => req<{ request_id: string }>("POST", "/admin/updates/run", { confirm: true, target, ...(build ? { mode: "build", confirm_build: true } : {}) }),
    updatesRollback: () => req<{ request_id: string }>("POST", "/admin/updates/rollback", { confirm: true }),
    updatesHelper: () => req<{ request_id: string }>("POST", "/admin/updates/helper", { confirm: true }),
    updatesBackup: () => req<{ request_id: string }>("POST", "/admin/updates/backup"),
    updatesPreflight: () => req<{ request_id: string }>("POST", "/admin/updates/preflight"),
    updatesRestore: (name: string, confirm: string) => req<{ request_id: string }>("POST", "/admin/updates/restore", { name, confirm }),
    updatesLog: (offset: number) => req<{ offset: number; size: number; text: string; reset: boolean; state: string; step_no: number; step_total: number; step_name: string; result: string; exit_code: number | null; finished_at: number }>("GET", `/admin/updates/log${qs({ offset })}`),
  },
};
