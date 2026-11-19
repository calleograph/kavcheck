/** Клиент раздела «Инвентаризация»: типы и вызовы /api/v1/inv/*. Отдельно от api.ts — раздел изолирован по маршрутам, компонентам и логике. */
import { ApiError, csrfToken, qs, req } from "../../api";

export type Q = Record<string, string | number | boolean | undefined | null>;
export type Perm = "view" | "create" | "edit" | "location" | "people" | "docs" | "repair" | "writeoff" | "count" | "import" | "refs" | "keys" | "templates";
export interface Ref { id: number; kind: string; name: string; code: string; parent_id: number | null; data: Record<string, unknown>; active: boolean }
export interface Prop { id: number; code: string; name: string; descr: string; type: string; options: string[]; default: unknown; required: boolean; type_ids: number[]; in_list: boolean; sort: number; active: boolean }
export interface Meta {
  refs: Ref[]; props: Prop[]; perms: Perm[]; scoped: boolean; scope_ids: number[]; cls: Record<string, string>; st: Record<string, string>; loc_kinds: Record<string, string>; ref_kinds: Record<string, string>;
  prop_types: Record<string, string>; roles: Record<string, string>; rels: Record<string, string>; metrics: Record<string, string>; doc_kinds: Record<string, string>; doc_short: Record<string, string>;
  doc_status: Record<string, string>; work_kinds: Record<string, string>; doc_columns: Record<string, string>;
  settings: { inv_prefix: string; inv_digits: number; warranty_days: number; license_days: number; transit_days: number; repair_days: number; stale_days: number; label_code: string; label_sheet: string };
}
export type Role = "user" | "owner" | "resp" | "mol" | "it";
export interface Asset {
  id: number; uid: string; inv_no: string; acc_no: string; serial: string; name: string; hostname: string; label: string; type_id: number | null; type: string; cls: string; cls_ru: string;
  model_id: number | null; model: string; manufacturer_id: number | null; manufacturer: string; status_id: number | null; status: string; st_cls: string; st_ru: string;
  location_id: number | null; location: string; loc_detail: string; user_id: number | null; owner_id: number | null; resp_id: number | null; mol_id: number | null; it_id: number | null;
  user: string; owner: string; resp: string; mol: string; it: string; dept_id: number | null; dept: string; branch_id: number | null; branch: string;
  purchase_date: string | null; received_date: string | null; commissioned_date: string | null; warranty_until: string | null; cost: number | null; cost_text: string; supplier_id: number | null; supplier: string;
  purchase_doc: string; parent_id: number | null; parent: string; rel: string; rel_ru: string; props: Record<string, unknown>; props_text: Record<string, string>; note: string;
  ksc_source_id: string | null; ksc_host_id: number | null; ksc_link: "" | "confirmed" | "auto" | "lost"; ksc_name: string; ext_ids: Record<string, unknown>; in_transit: boolean; transit_doc_id: number | null;
  created_at: string; created_by: string; updated_at: string; updated_by: string; version: number;
}
export interface DocBrief { id: number; no: string; kind: string; kind_ru: string; status: string; status_ru: string; date: string }
export interface FileRow { id: number; name: string; size: number; at: string; by: string }
export interface AssetCard extends Asset {
  children: Asset[]; docs: DocBrief[]; licenses: { id: number; name: string; assign_id: number; at: string; by: string }[]; files: FileRow[]; ksc_source: string; ksc_source_ok: boolean;
  can: Record<"edit" | "location" | "people" | "docs" | "repair" | "writeoff" | "create", boolean>;
}
export interface Change { f: string; label: string; old: string; new: string }
export interface Hist { id: number; at: string; by: string; kind: string; kind_ru: string; title: string; changes: Change[]; state: Record<string, string | number | null>; comment: string; basis: string; doc_id: number | null; doc_no: string }
export interface Tech {
  linked: boolean; error?: string; source?: string; source_id?: string; host_id?: number; missing?: boolean; fetched_at?: string;
  prepared?: { name: string; os: string; ip: string; group: string; last_connected: string | null; active: boolean; has_av: boolean };
  host?: { name: string; fqdn: string; os: string; last_connected: string | null };
  hw?: { known: boolean; virtual: boolean; line: string; cpus: { name: string; cores: number | null; threads: number | null; mhz: number | null }[]; ram_mb: number | null; ram_modules: { name: string; mb: number | null }[];
    disks: { name: string; total_gb: number | null; serial: string }[]; nics: { name: string; mac: string; speed_mbit: number | null }[]; board: { board: string; manuf: string; bios_version: string } | null; other: { type: string; name: string }[] };
  ids?: { board_serial: string; macs: string[] }; software?: { name: string; version: string; publisher: string; install_date: string | null }[]; issues?: string[];
  bi_owner?: { name: string; email: string; department: string; state_ru: string } | null;
}
export interface Loc { id: number; parent_id: number | null; kind: string; kind_ru: string; name: string; code: string; note: string; path: string; data: Record<string, unknown>; active: boolean; sort: number; n: number; total: number; by_cls?: Record<string, number>; in_scope?: boolean }
export interface Person { id: number; name: string; login: string; email: string; dept: string; title: string; phone: string; source: string; active: boolean; note: string; counts: Partial<Record<Role, number>> }
export interface PersonCard extends Person { assets: (Asset & { roles: string[] })[]; history: { at: string; by: string; asset_id: number; inv_no: string; name: string; role: string; action: string; title: string; doc_id: number | null }[] }
export interface BiCandidate { bi_id: number; name: string; email: string; dept: string; source: "bi" }
export interface Doc {
  id: number; no: string; kind: string; kind_ru: string; title: string; status: string; status_ru: string; date: string; from_location_id: number | null; from_location: string; to_location_id: number | null; to_location: string;
  from_person_id: number | null; from_person: string; to_person_id: number | null; to_person: string; resp_id: number | null; resp: string; basis: string; comment: string; data: Record<string, unknown>;
  history: { at: string; by: string; from: string; to: string; comment: string }[]; created_at: string; created_by: string; done_at: string | null; items_n: number | null; next: string[];
}
export interface DocItem { id: number; asset_id: number; snap: Record<string, unknown>; condition: string; note: string; current: Asset | null }
export interface DocCard extends Doc { items: DocItem[]; files: FileRow[]; can: { edit: boolean; move: boolean } }
export interface License {
  id: number; name: string; vendor: string; version: string; edition: string; type_id: number | null; type: string; category_id: number | null; category: string; metric: string; metric_ru: string; qty: number | null;
  match: string[]; purchase_date: string | null; valid_until: string | null; supplier_id: number | null; supplier: string; cost: number | null; cost_text: string; purchase_doc: string; resp_id: number | null; resp: string;
  note: string; key_set: boolean; active: boolean; updated_at: string; updated_by: string; installs: number | null; assigned: number; free: number | null; issues: string[]; usage_at: string | null; usage_errors: string[];
}
export interface LicenseCard extends License { assignments: { id: number; asset_id: number | null; asset: string; ksc: boolean; person_id: number | null; person: string; at: string; by: string; note: string }[]; files: FileRow[]; usage: Record<string, unknown>; can_key: boolean }
export interface Install { source_id: string; source: string; host_id: number; name: string; product: string; version: string; assigned: boolean; asset_id: number | null; inv_no: string }
export interface Overview {
  stats: { total: number; active: number; cost: number; cost_text: string; warranty_soon: number; no_owner: number; no_location: number; no_resp: number; computers: number; ksc_linked: number; ksc_unlinked: number; ksc_lost: number; in_transit: number; stale: number };
  by_cls: { cls: string; name: string; n: number }[]; by_st: { st: string; name: string; n: number }[]; licenses_soon: number; docs_open: { kind: string; name: string; n: number }[]; repair_long: number; transit_late: number;
  recent: { at: string; by: string; kind: string; title: string; asset_id: number; inv_no: string; name: string; doc_id: number | null }[]; ksc_sources: number; cfg: { warranty_days: number; license_days: number; stale_days: number };
}
export interface Group { id: number | string | null; name: string; n: number; cost: number; cost_text: string }
export interface KscHost { host_id: number; name: string; os: string; ip: string; group: string; last_connected: string | null; active: boolean; asset_id: number | null }
export interface View { id: number; name: string; params: Record<string, string>; shared: boolean; mine: boolean }
export interface ImportPreview { headers: string[]; rows: string[][]; total: number; mapping: Record<string, string>; fields: Record<string, string>; props: Record<string, string> }
export interface ImportResult { rows: number; created: number; updated: number; unchanged: number; skipped: number; errors: { row: number; error: string }[]; created_refs: { refs: number; locations: number; people: number }; dry_run: boolean }
export type Page<T> = { items: T[]; total: number; offset?: number; limit?: number };

export class FieldError extends ApiError { constructor(message: string, public errors: Record<string, string>) { super(422, message); } }

/** Запрос с разбором ошибок полей формы (422 → FieldError с errors по полям). */
async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const r = await fetch(`/api/v1${path}`, { method, headers: { Accept: "application/json", "Content-Type": "application/json", "X-CSRF-Token": csrfToken() }, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin" })
    .catch(() => { throw new ApiError(0, "Нет связи с сервером KAV Checker. Проверьте сеть и повторите.", "network"); });
  if (!r.ok) {
    let msg = `Ошибка ${r.status}`; let errors: Record<string, string> | null = null; let dup: number | undefined;
    try { const d = await r.json(); const det = d.detail; if (typeof det === "string") msg = det; else if (det && typeof det === "object" && !Array.isArray(det)) { msg = det.message ?? msg; errors = det.errors ?? null; dup = det.duplicate; } else if (typeof d.detail === "undefined" && d.message) msg = d.message; } catch { /* текст по умолчанию */ }
    if (errors) throw new FieldError(msg, errors);
    const e = new ApiError(r.status, msg); if (dup) (e as ApiError & { duplicate?: number }).duplicate = dup; throw e;
  }
  return r.json() as Promise<T>;
}

async function upload<T>(path: string, file: File | Blob, name: string, extra: Record<string, string> = {}): Promise<T> {
  const r = await fetch(`/api/v1${path}`, { method: "POST", headers: { "X-CSRF-Token": csrfToken(), "Content-Type": "application/octet-stream", "X-File-Name": encodeURIComponent(name), ...extra }, body: file, credentials: "same-origin" });
  if (!r.ok) { let msg = `Ошибка ${r.status}`; try { const d = await r.json(); if (typeof d.detail === "string") msg = d.detail; } catch { /* текст по умолчанию */ } throw new ApiError(r.status, msg); }
  return r.json() as Promise<T>;
}

export const inv = {
  meta: () => req<Meta>("GET", "/inv/meta"),
  overview: () => req<Overview>("GET", "/inv/overview"),
  assets: (p: Q) => req<Page<Asset>>("GET", `/inv/assets${qs(p)}`),
  groups: (by: string, p: Q) => req<{ by: string; items: Group[] }>("GET", `/inv/assets/groups${qs({ ...p, by })}`),
  asset: (id: number) => req<AssetCard>("GET", `/inv/assets/${id}`),
  create: (data: Record<string, unknown>, comment = "", force = false) => call<AssetCard>("POST", "/inv/assets", { data, comment, force }),
  update: (id: number, data: Record<string, unknown>, version: number, comment = "", basis = "") => call<AssetCard>("PUT", `/inv/assets/${id}`, { data, version, comment, basis }),
  bulk: (ids: number[], data: Record<string, unknown>, comment: string, dry_run = false) => call<{ found: number; changed?: number; would_change?: number; errors: { id: number; inv_no: string; error: string }[] }>("POST", "/inv/assets/bulk", { ids, data, comment, dry_run }),
  history: (id: number) => req<{ items: Hist[] }>("GET", `/inv/assets/${id}/history`),
  asof: (id: number, on: string) => req<{ on: string; exists: boolean; state: Record<string, string> | null; note?: string; event?: Hist }>("GET", `/inv/assets/${id}/asof${qs({ on })}`),
  tech: (id: number) => req<Tech>("GET", `/inv/assets/${id}/tech`),
  link: (id: number, source_id: string | null, host_id: number | null, comment = "") => req<{ ok: boolean }>("PUT", `/inv/assets/${id}/ksc`, { source_id, host_id, comment }),
  lookup: (code: string) => req<Asset>("GET", `/inv/lookup${qs({ code })}`),
  byUid: (uid: string) => req<{ id: number }>("GET", `/inv/a/${uid}`),
  byHost: (source: string, host: number) => req<{ asset: Asset | null; candidates: Asset[]; can_link: boolean; can_create: boolean; hidden?: boolean; host_name?: string }>("GET", `/inv/by-host${qs({ source, host })}`),
  kscHosts: (p: Q) => req<Page<KscHost> & { note?: string }>("GET", `/inv/ksc/hosts${qs(p)}`),
  kscImport: (source_id: string, host_ids: number[], status_id?: number | null, location_id?: number | null) => req<{ created: number; skipped: number; ids: number[] }>("POST", "/inv/ksc/import", { source_id, host_ids, status_id, location_id }),
  views: (page: string) => req<{ items: View[] }>("GET", `/inv/views${qs({ page })}`),
  addView: (page: string, name: string, params: Record<string, string>, shared: boolean) => req<{ id: number }>("POST", "/inv/views", { page, name, params, shared }),
  delView: (id: number) => req<{ ok: boolean }>("DELETE", `/inv/views/${id}`),
  upload: (owner: "asset" | "doc" | "license", oid: number, f: File) => upload<{ id: number }>(`/inv/files${qs({ owner, oid })}`, f, f.name),
  delFile: (id: number) => req<{ ok: boolean }>("DELETE", `/inv/files/${id}`),
  locations: () => req<{ items: Loc[]; unplaced: number }>("GET", "/inv/locations"),
  addLoc: (b: Partial<Loc>) => req<Loc>("POST", "/inv/locations", b),
  editLoc: (id: number, b: Partial<Loc>) => req<Loc>("PUT", `/inv/locations/${id}`, b),
  delLoc: (id: number) => req<{ deleted: boolean; note?: string }>("DELETE", `/inv/locations/${id}`),
  addRef: (b: Partial<Ref>) => req<Ref>("POST", "/inv/refs", b),
  editRef: (id: number, b: Partial<Ref>) => req<{ ok: boolean }>("PUT", `/inv/refs/${id}`, b),
  delRef: (id: number) => req<{ deleted: boolean; note?: string }>("DELETE", `/inv/refs/${id}`),
  addProp: (b: Partial<Prop>) => req<Prop>("POST", "/inv/props", b),
  editProp: (id: number, b: Partial<Prop>) => req<Prop>("PUT", `/inv/props/${id}`, b),
  delProp: (id: number) => req<{ ok: boolean }>("DELETE", `/inv/props/${id}`),
  people: (p: Q) => req<Page<Person> & { bi: BiCandidate[] }>("GET", `/inv/people${qs(p)}`),
  person: (id: number) => req<PersonCard>("GET", `/inv/people/${id}`),
  addPerson: (b: Partial<Person> & { bi_id?: number }) => req<Person>("POST", "/inv/people", b),
  editPerson: (id: number, b: Partial<Person>) => req<Person>("PUT", `/inv/people/${id}`, b),
  importHier: () => req<{ added: number; updated: number }>("POST", "/inv/people/import-hier"),
  docs: (p: Q) => req<Page<Doc>>("GET", `/inv/docs${qs(p)}`),
  doc: (id: number) => req<DocCard>("GET", `/inv/docs/${id}`),
  addDoc: (b: Record<string, unknown>) => req<DocCard>("POST", "/inv/docs", b),
  editDoc: (id: number, b: Record<string, unknown>) => req<DocCard>("PUT", `/inv/docs/${id}`, b),
  docStatus: (id: number, to: string, comment = "", data?: Record<string, unknown>) => req<{ status: string; changed: number }>("POST", `/inv/docs/${id}/status`, { to, comment, data }),
  printForm: (id: number) => req<Record<string, unknown>>("GET", `/inv/docs/${id}/print?fmt=json`),
  printUrl: (id: number, fmt: "html" | "pdf" | "docx") => `/api/v1/inv/docs/${id}/print?fmt=${fmt}`,
  labelsUrl: (ids: number[], fmt: "pdf" | "zpl" = "pdf") => `/api/v1/inv/labels?ids=${ids.join(",")}&fmt=${fmt}`,
  locLabelsUrl: (ids: number[]) => `/api/v1/inv/labels?locations=${ids.join(",")}`,
  fileUrl: (id: number) => `/api/v1/inv/files/${id}`,
  licenses: (p: Q) => req<{ items: License[]; total: number; usage_at: string | null; usage_requested: boolean }>("GET", `/inv/licenses${qs(p)}`),
  license: (id: number) => req<LicenseCard>("GET", `/inv/licenses/${id}`),
  addLicense: (b: Record<string, unknown>) => req<{ id: number }>("POST", "/inv/licenses", b),
  editLicense: (id: number, b: Record<string, unknown>) => req<{ ok: boolean }>("PUT", `/inv/licenses/${id}`, b),
  installs: (id: number) => req<{ items: Install[]; errors: string[]; days: number; note?: string }>("GET", `/inv/licenses/${id}/installs`),
  assign: (id: number, asset_ids: number[], person_ids: number[], note = "") => req<{ added: number }>("POST", `/inv/licenses/${id}/assign`, { asset_ids, person_ids, note }),
  unassign: (id: number, aid: number) => req<{ ok: boolean }>("DELETE", `/inv/licenses/${id}/assign/${aid}`),
  licKey: (id: number) => req<{ key: string }>("GET", `/inv/licenses/${id}/key`),
  recount: () => req<{ queued: boolean }>("POST", "/inv/licenses/recount"),
  importPreview: (f: File) => upload<ImportPreview>("/inv/import/preview", f, f.name),
  importRun: (f: File, mapping: Record<string, string>, p: { mode: "create" | "upsert"; create_refs: boolean; dry_run: boolean }) =>
    upload<ImportResult>(`/inv/import/run${qs(p)}`, f, f.name, { "X-Mapping": encodeURIComponent(JSON.stringify(mapping)) }),
};

/** Параметры отбора списка оборудования: адресная строка ↔ запрос (один набор для списка, группировки, массовых операций и отчёта). */
export const FILTER_KEYS = ["q", "cls", "type_id", "model_id", "manufacturer_id", "status_id", "st", "location", "no_location", "person", "role", "dept_id", "branch_id", "supplier_id", "ksc", "warranty", "transit", "no_owner", "no_resp", "stale", "parent"] as const;
export const money = (k: number | null | undefined) => (k === null || k === undefined ? "" : `${(k / 100).toLocaleString("ru-RU", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ₽`);
