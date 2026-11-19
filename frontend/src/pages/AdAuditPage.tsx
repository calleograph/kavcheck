import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type AdAccount, type AdAccountCard, type AdCategory, type AdDecision, type AdEvent, type AdFinding, type AdRun, type AdState, type ApiError } from "../api";
import type { Ctx } from "../App";
import { CompactList } from "../components/CompactList";
import { Modal } from "../components/Dialogs";
import { FilterBar } from "../components/FilterBar";
import { Icon } from "../components/Icons";
import { ListFoot, useInfinite, useKept, usePanel, type Chunk } from "../components/Infinite";
import { QuickReportPanel } from "../components/QuickReport";
import { useToast } from "../components/Toast";
import { Empty, PageHead, Segmented, SkelRows, SortTh, Tabs } from "../components/ui";
import { fmt, fmtDate, num, plural } from "../util";

type Tab = "overview" | "findings" | "accounts" | "passwords" | "activity" | "privileged" | "resets" | "runs";
const TABS: { id: Tab; label: string }[] = [{ id: "overview", label: "Обзор" }, { id: "findings", label: "Замечания" }, { id: "accounts", label: "Учётные записи" }, { id: "passwords", label: "Пароли" },
  { id: "activity", label: "Активность" }, { id: "privileged", label: "Админ. и сервисные" }, { id: "resets", label: "Смена и сброс пароля" }, { id: "runs", label: "Проверки" }];
const CAT_RU: Record<AdCategory, string> = { user: "Пользователь", admin: "Административная", service: "Сервисная", temp: "Временная", contractor: "Подрядчик", undefined: "Не определено" };
const SEV_TONE: Record<string, string> = { critical: "err", high: "err", medium: "warn", low: "" };
const SEV_RU: Record<string, string> = { critical: "критическое", high: "высокое", medium: "среднее", low: "низкое" };
const DEC: [AdDecision["state"], string][] = [["open", "Открыто"], ["in_progress", "В работе"], ["fixed", "Устранено"], ["exception", "Исключение"]];
const OP_RU: Record<string, string> = { change: "Смена пользователем (4723)", reset: "Сброс пароля (4724)", no_event: "Событие не найдено", before_logs: "Раньше сохранённых журналов", no_logs: "Журналов нет", no_pwd: "Пароль не задан" };
const SRC_RU: Record<string, string> = { dc: "lastLogon всех контроллеров домена — точная дата", llt: "lastLogonTimestamp — реплицируется с задержкой до ~14 суток", none: "нет данных" };
const BUCKETS: [string, string, string][] = [["gt180", "более 180 дней", "critical"], ["le180", "90–180 дней", "high"], ["le90", "30–90 дней", "warning"], ["le30", "до 30 дней", "ok"], ["unknown", "дата неизвестна", "none"]];

type Report = { params: Record<string, unknown>; title: string };
const days = (n: number | null | undefined) => (n === null || n === undefined ? "" : `${num(n)} ${plural(n, "день", "дня", "дней")}`);

/** Раздел «Аудит домена»: ежемесячная и квартальная проверка учётных записей AD, замечания с решениями, карточка учётной записи, смена и сброс пароля по журналам контроллеров. Только чтение домена. */
export default function AdAuditPage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const tab = (TABS.some((t) => t.id === sp.get("tab")) ? sp.get("tab") : "overview") as Tab;
  const run = sp.get("run") ?? "";
  const [st, setSt] = useState<AdState | null>(null); const [err, setErr] = useState("");
  const [acc, setAcc] = usePanel<string>("adaudit-acc");
  const [report, setReport] = useState<Report | null>(null);
  const [toast, show] = useToast();
  const load = useCallback(() => api.adaudit.state().then((s) => { setSt(s); setErr(""); }).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); }, [load]);
  const busy = !!st && (st.requested || st.last?.status === "running");
  useEffect(() => { if (!busy) return; const t = window.setInterval(() => void load(), 8000); return () => window.clearInterval(t); }, [busy, load]);
  const go = (t: Tab, extra: Record<string, string> = {}) => setSp((p) => { p.set("tab", t); for (const [k, v] of Object.entries(extra)) { if (v) p.set(k, v); else p.delete(k); } return p; });
  const start = async (kind: "manual" | "quarterly") => { try { await api.adaudit.run(kind); show(kind === "quarterly" ? "Квартальная проверка поставлена в очередь" : "Проверка поставлена в очередь"); void load(); } catch (e) { show((e as ApiError).message, "error"); } };
  const latest = st?.latest ?? null;
  const viewing = run && latest && run !== latest.id;
  const open = (r: Report) => setReport({ ...r, params: { ...r.params, ...(run ? { run } : {}) } });
  return (
    <section className="adaudit">
      <PageHead title="Аудит домена" lede="Регулярная проверка учётных записей Active Directory: пароли и сроки, активность, привилегированные и сервисные учётные записи, смена и сброс пароля. Раздел только читает домен и ничего в нём не меняет.">
        <div className="row">
          <button className="btn" disabled={busy} onClick={() => void start("quarterly")} title="Квартальная проверка: те же проверки, отчёт с разделом неиспользуемых учётных записей и давних паролей"><Icon name="clock" size={16} />Квартальная</button>
          <button className="btn primary" disabled={busy} aria-busy={busy} onClick={() => void start("manual")}><Icon name="refresh" size={16} />{busy ? "Идёт проверка…" : "Запустить проверку"}</button>
        </div>
      </PageHead>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {st && <RunLine st={st} viewing={!!viewing} run={run} onBack={() => setSp((p) => { p.delete("run"); return p; })} />}
      {!st && !err && <div className="card"><SkelRows rows={4} cols={4} /></div>}
      {st && !latest && (
        <div className="card"><Empty icon="users" title="Проверок домена ещё не было" action={<button className="btn primary" disabled={busy} onClick={() => void start("manual")}>{busy ? "Идёт проверка…" : "Запустить первую проверку"}</button>}>
          Раздел использует подключение LDAPS из «Администрирование → LDAPS» (только чтение). Сроки паролей, категории учётных записей и расписание — в «Администрирование → Аудит домена».</Empty></div>)}
      {st && latest && <>
        <Tabs label="Раздел аудита" value={tab} onChange={(t) => go(t, { code: "", bucket: "" })} items={TABS.map((t) => ({ ...t, count: t.id === "findings" ? st.open ?? undefined : undefined }))} />
        {tab === "overview" && <Overview st={st} run={run} go={go} report={open} />}
        {tab === "findings" && <FindingsView st={st} run={run} onOpen={setAcc} report={open} />}
        {tab === "accounts" && <AccountsView key="a" run={run} onOpen={setAcc} report={open} views={[["", "Все"], ["enabled", "Активные"], ["disabled", "Отключённые"], ["with_findings", "С замечаниями"], ["must_change", "Сменить при входе"]]} reportView={(v) => (v === "enabled" ? "active" : "accounts")} cats />}
        {tab === "passwords" && <PasswordsView run={run} onOpen={setAcc} report={open} policy={st.policy} />}
        {tab === "activity" && <AccountsView key="act" run={run} onOpen={setAcc} report={open} views={[["inactive", `Не входили > ${st.policy.inactive_days} дн.`], ["never", "Ни разу не входили"], ["locked", "Заблокированные"], ["new", `Созданы за ${st.policy.new_days} дн.`], ["expired", "Истёк срок"], ["disabled", "Отключённые"]]} reportView={() => "unused"} sortDefault="idle" />}
        {tab === "privileged" && <AccountsView key="priv" run={run} onOpen={setAcc} report={open} catViews reportView={() => "privileged"} />}
        {tab === "resets" && <ResetsView st={st} run={run} onOpen={setAcc} report={open} onImported={load} />}
        {tab === "runs" && <RunsView current={run || latest.id} onPick={(id) => setSp((p) => { if (id === latest.id) p.delete("run"); else p.set("run", id); p.set("tab", "overview"); return p; })} />}
      </>}
      {acc && <AccountPanel guid={acc} run={run} onClose={() => setAcc(null)} onChanged={load} />}
      {report && <QuickReportPanel kind="quick_adaudit" title={report.title} lede="Отчёт по сохранённой проверке домена: учётные записи, даты, основания, категория, статус и решения администратора" params={report.params}
        options={{}} activityDays={ctx.me.activity_days} canReport onClose={() => setReport(null)} />}
      {toast}
    </section>
  );
}

function RunLine({ st, viewing, run, onBack }: { st: AdState; viewing: boolean; run: string; onBack: () => void }) {
  const r = st.latest; const failed = st.last && st.last.status === "failed" ? st.last : null; const running = st.last?.status === "running" || st.requested;
  return (
    <div className="ada-runline">
      {r && <span><Icon name="history" size={15} />{viewing ? <>Просмотр прежней проверки · <button type="button" className="link-btn" onClick={onBack}>к последней</button></> : <>Последняя проверка {fmt(r.finished_at)} · {r.kind_ru}</>} · {r.domain}</span>}
      {running && <span className="badge accent"><span className="spin sm" />проверка выполняется</span>}
      {failed && !running && <span className="badge err" title={failed.message}>последняя попытка {fmt(failed.started_at)} не удалась</span>}
      {st.schedule.enabled ? <span className="muted">по расписанию: {st.schedule.day}-го числа в {st.schedule.time} ({st.schedule.timezone}){st.next_run ? `, следующая ${fmt(st.next_run)}` : ""}</span> : <span className="muted">расписание выключено</span>}
      {run && !viewing ? null : null}
      {failed && !running && <span className="muted small ada-fail">{failed.message}</span>}
    </div>
  );
}

function Overview({ st, run, go, report }: { st: AdState; run: string; go: (t: Tab, x?: Record<string, string>) => void; report: (r: Report) => void }) {
  const [r, setR] = useState<AdRun | null>(st.latest);
  useEffect(() => { if (!run) { setR(st.latest); return; } api.adaudit.runs().then((x) => setR(x.items.find((i) => i.id === run) ?? st.latest)).catch(() => setR(st.latest)); }, [run, st.latest]);
  if (!r) return null;
  const s = r.stats as Record<string, number>;
  const v = (k: string) => Number(s[k] ?? 0);
  const enabled = v("enabled") || 1;
  const crit = st.by_code.filter((c) => c.severity === "critical" || c.severity === "high").reduce((a, c) => a + c.open + c.in_progress, 0);
  const cov = st.latest?.coverage; const logs = cov ? Object.keys(cov.logs ?? {}) : [];
  return (
    <>
      <div className="meters">
        <div className="meter"><span className="l">Учётных записей</span><span className="v">{num(v("accounts"))}</span><span className="t">активных {num(v("enabled"))}, отключённых {num(v("disabled"))}</span></div>
        <div className="meter"><button type="button" className="meter-link" onClick={() => go("findings", { decision: "unresolved" })}><span className="l">Требуют внимания</span><span className={`v ${st.open ? "warn-text" : ""}`}>{num(st.open ?? 0)}</span><span className="t">замечаний без решения или в работе; исключений — {num(st.exceptions ?? 0)}</span></button></div>
        <div className="meter"><button type="button" className="meter-link" onClick={() => go("findings", { severity: "high" })}><span className="l">Критических и высоких</span><span className={`v ${crit ? "bad-text" : ""}`}>{num(crit)}</span><span className="t">открытых замечаний</span></button></div>
        <div className="meter"><button type="button" className="meter-link" onClick={() => go("findings", { carried: "1" })}><span className="l">С прошлых проверок</span><span className={`v ${st.carried ? "warn-text" : ""}`}>{num(st.carried)}</span><span className="t">{s.prev_run ? `новых ${num(v("new_since_prev"))}, устранено ${num(v("fixed_since_prev"))}` : "первая проверка — сравнивать не с чем"}</span></button></div>
      </div>
      <div className="split ada-split">
        <div className="card">
          <div className="card-head"><h2>Что требует внимания</h2><div className="spacer" /><button className="btn mini" onClick={() => report({ title: "Результаты проверки домена", params: { view: "audit" } })}><Icon name="file" size={15} />Отчёт о проверке</button></div>
          {st.by_code.length === 0 ? <p className="muted">Замечаний нет.</p> : (
            <ul className="ada-issues">{st.by_code.map((c) => (
              <li key={c.code}><button type="button" className="ada-issue" onClick={() => go("findings", { code: c.code })}>
                <span className={`badge ${SEV_TONE[c.severity]}`}>{SEV_RU[c.severity]}</span>
                <span className="ada-issue-t">{c.title}{c.status === "review" && <span className="sub muted">требует дополнительной проверки</span>}</span>
                <span className="ada-issue-n"><b>{num(c.open + c.in_progress)}</b>{c.exception > 0 && <span className="sub muted">+{num(c.exception)} искл.</span>}</span>
              </button></li>))}</ul>)}
        </div>
        <div className="ada-side">
          <div className="card">
            <div className="card-head"><h2>Пароли активных учётных записей</h2></div>
            <ul className="hbars" aria-label="Давность смены пароля">{BUCKETS.map(([k, l, tone]) => { const n = v(`pwd_${k}`); return (
              <li key={k}><button type="button" className={`hbar tone-${tone} ${n ? "" : "zero"}`} disabled={!n} onClick={() => go("passwords", { bucket: k })}>
                <span className="hb-l">{l}</span><span className="hb-track"><i style={{ width: `${Math.round((n / enabled) * 100)}%` }} /></span><span className="hb-v">{num(n)}</span></button></li>); })}</ul>
            <p className="muted small">Пароль без срока действия — <button type="button" className="link-btn" onClick={() => go("passwords", { bucket: "" })}>{num(v("pne"))}</button>. Сроки: {Object.entries(st.policy.pwd_days).map(([k, d]) => `${CAT_RU[k as AdCategory].toLowerCase()} — ${d} дн.`).join(", ")}.</p>
          </div>
          <div className="card">
            <div className="card-head"><h2>Категории</h2></div>
            <ul className="hbars">{(Object.keys(CAT_RU) as AdCategory[]).map((k) => { const n = v(`cat_${k}`); return (
              <li key={k}><button type="button" className={`hbar tone-${k === "undefined" ? "warning" : k === "admin" ? "critical" : "protection"} ${n ? "" : "zero"}`} disabled={!n} onClick={() => go(k === "user" ? "accounts" : "privileged", { cat: k })}>
                <span className="hb-l">{CAT_RU[k]}</span><span className="hb-track"><i style={{ width: `${Math.round((n / Math.max(1, v("accounts"))) * 100)}%` }} /></span><span className="hb-v">{num(n)}</span></button></li>); })}</ul>
          </div>
          <div className="card">
            <div className="card-head"><h2>Смена и сброс пароля</h2></div>
            {logs.length ? <p className="small">Журналы контроллеров загружены: {logs.join(", ")}{cov?.logs_missing?.length ? <>; <b className="warn-text">нет журналов: {cov.logs_missing.join(", ")}</b></> : ""}. Сброс без последующей смены — <button type="button" className="link-btn" onClick={() => go("resets")}><b className={v("reset_pending") ? "bad-text" : ""}>{num(v("reset_pending"))}</b></button>.</p>
              : <p className="small">Журналы безопасности контроллеров не загружены: способ последней смены пароля неизвестен, сбросы (Reset Password) не выявляются. <button type="button" className="link-btn" onClick={() => go("resets")}>Как загрузить</button></p>}
            <button className="btn mini" onClick={() => report({ title: "Аудит домена: сводка для руководства", params: { view: "summary" } })}><Icon name="file" size={15} />Сводка для руководства</button>
          </div>
        </div>
      </div>
      {!!r.notes?.length && <details className="disclosure"><summary>Примечания проверки ({r.notes.length})</summary><ul className="small">{r.notes.map((n, i) => <li key={i}>{n}</li>)}</ul></details>}
    </>
  );
}

function SevBadge({ s }: { s: string }) {
  return <span className={`badge ${SEV_TONE[s] ?? ""}`}>{SEV_RU[s] ?? s}</span>;
}

function DecisionBadge({ d }: { d: AdDecision | null }) {
  if (!d) return <span className="muted small">решения нет</span>;
  const tone = d.state === "exception" ? (d.expired ? "warn" : "accent") : d.state === "fixed" ? "ok" : d.state === "in_progress" ? "warn" : "";
  return <><span className={`badge ${tone}`}>{d.state_ru}{d.expired ? ": срок истёк" : ""}</span>{(d.owner || d.due) && <span className="sub small">{[d.owner, d.due && `до ${fmtDate(d.due)}`].filter(Boolean).join(", ")}</span>}</>;
}

/** Решение по одному или нескольким замечаниям: статус, ответственный, срок, комментарий. Исключение требует основания. */
function DecisionForm({ keys, init, onDone, onCancel }: { keys: string[]; init?: AdDecision | null; onDone: () => void; onCancel: () => void }) {
  const [state, setState] = useState<AdDecision["state"]>(init?.state ?? "in_progress");
  const [owner, setOwner] = useState(init?.owner ?? ""); const [due, setDue] = useState(init?.due ?? ""); const [comment, setComment] = useState(init?.comment ?? "");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const save = async () => { setBusy(true); setErr(""); try { await api.adaudit.decide({ keys, state, owner: owner.trim(), due: due || null, comment: comment.trim() }); onDone(); } catch (e) { setErr((e as ApiError).message); } setBusy(false); };
  return (
    <div className="ada-decide">
      <Segmented label="Решение" value={state} onChange={setState} options={DEC} />
      <div className="cols">
        <label>Ответственный<input value={owner} onChange={(e) => setOwner(e.target.value)} maxLength={200} placeholder="ФИО или подразделение" /></label>
        <label>{state === "exception" ? "Исключение действует до" : "Срок устранения"}<input type="date" value={due} onChange={(e) => setDue(e.target.value)} /></label>
      </div>
      <label>Комментарий{state === "exception" && <span className="help">Основание исключения обязательно: кем и когда согласовано</span>}<textarea rows={2} value={comment} onChange={(e) => setComment(e.target.value)} maxLength={4000} /></label>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="row"><button type="button" className="btn ghost" onClick={onCancel}>Отмена</button><button type="button" className="btn primary" aria-busy={busy} onClick={() => void save()}>Сохранить{keys.length > 1 ? ` (${keys.length})` : ""}</button></div>
    </div>
  );
}

function FindingsView({ st, run, onOpen, report }: { st: AdState; run: string; onOpen: (g: string) => void; report: (r: Report) => void }) {
  const [sp, setSp] = useSearchParams();
  const code = sp.get("code") ?? ""; const severity = sp.get("severity") ?? ""; const carried = sp.get("carried") === "1"; const gone = sp.get("gone") === "1";
  const set = (k: string, v: string) => setSp((p) => { if (v) p.set(k, v); else p.delete(k); return p; });
  const [q, setQ] = useKept("ada.f.q", ""); const [applied, setApplied] = useState(q);
  const [status, setStatus] = useKept<"" | "violation" | "review">("ada.f.status", "");
  const [cat, setCat] = useKept("ada.f.cat", ""); const [decision, setDecision] = useState(sp.get("decision") ?? "unresolved");
  const [sel, setSel] = useState<string[]>([]); const [deciding, setDeciding] = useState(false);
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 300); return () => window.clearTimeout(t); }, [q]);
  const list = useInfinite<AdFinding>(`ada-f:${run}`, [applied, code, severity, status, cat, decision, carried, gone, run], (offset, limit) =>
    api.adaudit.findings({ run: run || undefined, q: applied, code, severity: severity === "high" ? "" : severity, status, category: cat, decision: gone ? "" : decision, carried: carried || undefined, gone: gone || undefined, offset, limit })
      .then((r) => (severity === "high" ? { ...r, items: r.items.filter((f) => f.severity === "high" || f.severity === "critical") } : r)) as unknown as Promise<Chunk<AdFinding>>);
  const toggle = (k: string) => setSel((s) => (s.includes(k) ? s.filter((x) => x !== k) : [...s, k]));
  const title = st.by_code.find((c) => c.code === code)?.title;
  return (
    <>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Логин или имя", label: "Поиск замечаний" }}
        primary={<>
          <Segmented label="Статус проверки" value={status} onChange={setStatus} options={[["", "Все"], ["violation", "Нарушения"], ["review", "Требуют проверки"]]} />
          <label className="field">Решение<select value={gone ? "gone" : decision} onChange={(e) => { if (e.target.value === "gone") set("gone", "1"); else { set("gone", ""); setDecision(e.target.value); } }}>
            <option value="unresolved">Не решённые</option><option value="">Все</option><option value="open">Без решения</option><option value="in_progress">В работе</option><option value="exception">Исключения</option><option value="fixed">Отмечены устранёнными, но найдены снова</option><option value="gone">Устранены с прошлой проверки</option></select></label>
        </>}
        more={<>
          <label className="field">Замечание<select value={code} onChange={(e) => set("code", e.target.value)}><option value="">Все</option>{st.by_code.map((c) => <option key={c.code} value={c.code}>{c.title}</option>)}</select></label>
          <label className="field">Важность<select value={severity} onChange={(e) => set("severity", e.target.value)}><option value="">Любая</option><option value="high">Критическая и высокая</option><option value="critical">Критическая</option><option value="medium">Средняя</option><option value="low">Низкая</option></select></label>
          <label className="field">Категория<select value={cat} onChange={(e) => setCat(e.target.value)}><option value="">Все</option>{(Object.keys(CAT_RU) as AdCategory[]).map((k) => <option key={k} value={k}>{CAT_RU[k]}</option>)}</select></label>
          <label className="check"><input type="checkbox" className="switch" checked={carried} onChange={(e) => set("carried", e.target.checked ? "1" : "")} />Остались с прошлых проверок</label>
        </>} moreActive={[code, severity, cat, carried ? "1" : ""].filter(Boolean).length}
        chips={[...(code ? [{ id: "code", label: title ?? code, onRemove: () => set("code", "") }] : []), ...(severity ? [{ id: "sev", label: severity === "high" ? "Критические и высокие" : `Важность: ${SEV_RU[severity]}`, onRemove: () => set("severity", "") }] : []),
          ...(carried ? [{ id: "car", label: "С прошлых проверок", onRemove: () => set("carried", "") }] : []), ...(gone ? [{ id: "gone", label: "Устранены с прошлой проверки", onRemove: () => set("gone", "") }] : []),
          ...(cat ? [{ id: "cat", label: CAT_RU[cat as AdCategory], onRemove: () => setCat("") }] : [])]}
        onReset={() => { setQ(""); setStatus(""); setCat(""); setSp((p) => { ["code", "severity", "carried", "gone"].forEach((k) => p.delete(k)); return p; }); }}
        count={{ n: list.initial ? null : list.total, noun: ["замечание", "замечания", "замечаний"] }} onRefresh={() => list.reload()} refreshing={list.refreshing}
        report={{ onClick: () => report({ title: title ? `Замечания: ${title}` : "Замечания аудита домена", params: { view: "findings", code, q: applied, category: cat, severity: severity === "high" ? "" : severity } }) }} />
      {sel.length > 0 && !gone && <div className="ada-bulk"><span><b>{sel.length}</b> {plural(sel.length, "замечание выбрано", "замечания выбраны", "замечаний выбрано")}</span><button className="btn mini primary" onClick={() => setDeciding(true)}>Решение…</button><button className="btn mini ghost" onClick={() => setSel([])}>Снять выбор</button></div>}
      {deciding && <Modal title={`Решение по ${sel.length} ${plural(sel.length, "замечанию", "замечаниям", "замечаниям")}`} onClose={() => setDeciding(false)}>
        <DecisionForm keys={sel} onCancel={() => setDeciding(false)} onDone={() => { setDeciding(false); setSel([]); list.reload(); }} /></Modal>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={6} /> : !list.items.length ? <Empty icon="check" title={gone ? "Устранённых с прошлой проверки нет" : "Замечаний нет"}>Измените условия отбора.</Empty> : (
          <table className="table">
            <thead><tr>{!gone && <th className="check"><span className="sr-only">Выбор</span></th>}<th>Важность</th><th>Учётная запись</th><th className="hide-sm">Категория</th><th>Замечание</th><th className="hide-md">Обнаружено</th><th>Решение</th></tr></thead>
            <tbody>{list.items.map((f) => (
              <tr key={f.key} className={`${f.code === "reset" ? "row-bad" : ""} ${sel.includes(f.key) ? "sel" : ""}`}>
                {!gone && <td className="check"><input type="checkbox" aria-label={`Выбрать: ${f.login}, ${f.title}`} checked={sel.includes(f.key)} onChange={() => toggle(f.key)} /></td>}
                <td><SevBadge s={f.severity} />{f.status === "review" && <span className="sub small muted">проверить</span>}</td>
                <td><button type="button" className="link-btn strong-link" onClick={() => onOpen(f.guid)}>{f.login}</button><span className="sub">{f.name}</span></td>
                <td className="hide-sm small">{f.category_ru}</td>
                <td className="ada-basis"><b>{f.title}</b><span className="sub small">{f.basis}</span></td>
                <td className="hide-md small nowrap">{fmtDate(f.first_seen)}{f.runs_n > 1 && <span className="sub warn-text">{f.runs_n}-я проверка подряд</span>}</td>
                <td><DecisionBadge d={f.decision} /></td>
              </tr>))}</tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
    </>
  );
}

function AccountRow({ a, onOpen }: { a: AdAccount; onOpen: (g: string) => void }) {
  return (
    <tr className={a.max_sev >= 3 ? "row-warn" : ""}>
      <td><button type="button" className="link-btn strong-link" onClick={() => onOpen(a.guid)}>{a.login}</button><span className="sub">{a.name}</span>{a.description && <span className="sub small muted ada-desc">{a.description}</span>}</td>
      <td className="small hide-sm">{a.category_ru}</td>
      <td>{!a.enabled ? <span className="badge">отключена</span> : a.locked ? <span className="badge warn">заблокирована</span> : <span className="badge ok">активна</span>}</td>
      <td className="small nowrap">{a.must_change ? <span className="warn-text">сменить при входе</span> : a.pwd_last_set ? <>{fmtDate(a.pwd_last_set)}<span className="sub">{days(a.pwd_age)}</span></> : "—"}{a.pne && <span className="sub"><span className="badge err">бессрочный</span></span>}</td>
      <td className="small nowrap" title={SRC_RU[a.last_logon_src]}>{a.last_logon ? <>{fmtDate(a.last_logon)}<span className="sub">{days(a.idle_days)}{a.last_logon_src === "llt" ? " ±14" : ""}</span></> : <span className="muted">не входила</span>}</td>
      <td className="small nowrap hide-md">{fmtDate(a.created)}</td>
      <td className="num">{a.findings_n ? <span className={`badge ${a.max_sev >= 3 ? "err" : a.max_sev === 2 ? "warn" : ""}`}>{a.findings_n}</span> : <span className="muted">—</span>}</td>
    </tr>
  );
}

function AccountsView({ run, onOpen, report, views, reportView, cats, catViews, sortDefault = "risk" }: { run: string; onOpen: (g: string) => void; report: (r: Report) => void; views?: [string, string][]; reportView: (v: string) => string;
  cats?: boolean; catViews?: boolean; sortDefault?: string }) {
  const [sp] = useSearchParams();
  const [q, setQ] = useState(""); const [applied, setApplied] = useState("");
  const [view, setView] = useState(views?.[0]?.[0] ?? "");
  const [cat, setCat] = useState(sp.get("cat") ?? (catViews ? "admin" : ""));
  const [sort, setSort] = useState(sortDefault); const [desc, setDesc] = useState(true);
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 300); return () => window.clearTimeout(t); }, [q]);
  const list = useInfinite<AdAccount>(`ada-a:${run}:${catViews ? "p" : views?.[0]?.[0] ?? ""}`, [applied, view, cat, sort, desc, run], (offset, limit) =>
    api.adaudit.accounts({ run: run || undefined, q: applied, view, category: cat, sort, desc, offset, limit }) as unknown as Promise<Chunk<AdAccount>>);
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(true); } };
  return (
    <>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Логин, имя, описание, подразделение", label: "Поиск учётных записей" }}
        primary={<>
          {views && <Segmented label="Отбор" value={view} onChange={setView} options={views} />}
          {catViews && <Segmented label="Категория" value={cat as AdCategory} onChange={(v) => setCat(v)} options={[["admin", "Административные"], ["service", "Сервисные"], ["temp", "Временные"], ["contractor", "Подрядчики"], ["undefined", "Не определено"]]} />}
          {cats && <label className="field">Категория<select value={cat} onChange={(e) => setCat(e.target.value)}><option value="">Все</option>{(Object.keys(CAT_RU) as AdCategory[]).map((k) => <option key={k} value={k}>{CAT_RU[k]}</option>)}</select></label>}
        </>}
        chips={[...(q ? [{ id: "q", label: `Поиск: ${q}`, onRemove: () => setQ("") }] : []), ...(cats && cat ? [{ id: "cat", label: CAT_RU[cat as AdCategory], onRemove: () => setCat("") }] : [])]}
        onReset={() => { setQ(""); if (cats) setCat(""); }}
        count={{ n: list.initial ? null : list.total, noun: ["учётная запись", "учётные записи", "учётных записей"] }} onRefresh={() => list.reload()} refreshing={list.refreshing}
        report={{ onClick: () => report({ title: "Учётные записи домена", params: { view: reportView(view), q: applied, category: cat } }) }} />
      {catViews && cat === "service" && <p className="muted small fbar-note">Сервисным учётным записям допускается бессрочный пароль только как согласованное исключение с ручной сменой не реже раза в 180 дней; ответственный и назначение должны быть указаны (manager или info, Description).</p>}
      {catViews && cat === "undefined" && <p className="muted small fbar-note">Категория не определена: признаков недостаточно или они противоречат друг другу. Откройте карточку и назначьте категорию вручную.</p>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={7} /> : !list.items.length ? <Empty icon="users" title="Учётных записей нет">Под условия отбора ничего не подходит.</Empty> : (
          <table className="table">
            <thead><tr><SortTh k="login" label="Учётная запись" sort={sort} desc={desc} onSort={onSort} /><th className="hide-sm">Категория</th><th>Состояние</th>
              <SortTh k="pwd_age" label="Пароль изменён" sort={sort} desc={desc} onSort={onSort} /><SortTh k="idle" label="Последний вход" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="created" label="Создана" sort={sort} desc={desc} onSort={onSort} className="hide-md" /><SortTh k="risk" label="Замечания" sort={sort} desc={desc} onSort={onSort} /></tr></thead>
            <tbody>{list.items.map((a) => <AccountRow key={a.guid} a={a} onOpen={onOpen} />)}</tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
    </>
  );
}

function PasswordsView({ run, onOpen, report, policy }: { run: string; onOpen: (g: string) => void; report: (r: Report) => void; policy: AdState["policy"] }) {
  const [sp, setSp] = useSearchParams();
  const bucket = sp.get("bucket") ?? "";
  const mode = bucket ? "age" : "pne";
  const list = useInfinite<AdAccount>(`ada-p:${run}`, [bucket, run], (offset, limit) =>
    api.adaudit.accounts({ run: run || undefined, view: bucket ? "enabled" : "pne", bucket, sort: "pwd_age", desc: true, offset, limit }) as unknown as Promise<Chunk<AdAccount>>);
  return (
    <>
      <div className="toolbar">
        <Segmented label="Проверка паролей" value={mode} onChange={(m) => setSp((p) => { if (m === "pne") p.delete("bucket"); else p.set("bucket", "gt180"); return p; })} options={[["pne", "Бессрочный пароль"], ["age", "Давность смены"]]} />
        {mode === "age" && <Segmented label="Давность" value={bucket} onChange={(b) => setSp((p) => { p.set("bucket", b); return p; })} options={BUCKETS.map(([k, l]) => [k, l] as [string, string])} />}
        <div className="spacer" />
        <button className="btn mini primary" onClick={() => report({ title: mode === "pne" ? "Пароль без срока действия" : "Давность смены паролей", params: { view: mode === "pne" ? "pne" : "pwd_age" } })}><Icon name="file" size={15} />Сформировать отчёт</button>
      </div>
      <p className="muted small fbar-note">{mode === "pne" ? "Флаг Password Never Expires: у административных — критическое замечание, у обычных — высокое; у сервисных допустим как согласованное исключение с ручной сменой (не реже раза в 180 дней)." :
        `Только активные учётные записи. Сроки смены по категориям: ${Object.entries(policy.pwd_days).map(([k, d]) => `${CAT_RU[k as AdCategory].toLowerCase()} — ${d} дн.`).join(", ")}.`}</p>
      <div className="table-scroll">{list.initial ? <SkelRows cols={7} /> : !list.items.length ? <Empty icon="check" title="Учётных записей нет" /> : (
        <table className="table"><thead><tr><th>Учётная запись</th><th className="hide-sm">Категория</th><th>Состояние</th><th>Пароль изменён</th><th>Последний вход</th><th className="hide-md">Создана</th><th>Замечания</th></tr></thead>
          <tbody>{list.items.map((a) => <AccountRow key={a.guid} a={a} onOpen={onOpen} />)}</tbody></table>)}</div>
      <ListFoot list={list} />
    </>
  );
}

function ResetsView({ st, run, onOpen, report, onImported }: { st: AdState; run: string; onOpen: (g: string) => void; report: (r: Report) => void; onImported: () => void }) {
  const [kind, setKind] = useState<"" | "reset" | "change">("reset");
  const [q, setQ] = useState(""); const [applied, setApplied] = useState("");
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 300); return () => window.clearTimeout(t); }, [q]);
  const pending = useInfinite<AdFinding>(`ada-rp:${run}`, [run], (offset, limit) => api.adaudit.findings({ run: run || undefined, code: "reset", decision: "", offset, limit }) as unknown as Promise<Chunk<AdFinding>>);
  const evs = useInfinite<AdEvent>("ada-ev", [kind, applied, st.import?.at], (offset, limit) => api.adaudit.events({ kind, q: applied, offset, limit }) as unknown as Promise<Chunk<AdEvent>>);
  const [toast, show] = useToast(); const [busy, setBusy] = useState(false);
  const upload = async (f: File | undefined) => { if (!f) return; setBusy(true); try { const r = await api.adaudit.upload(f); show(`Загружено событий: ${r.added} из ${r.events}. ${r.note}`); onImported(); evs.reload(); } catch (e) { show((e as ApiError).message, "error"); } setBusy(false); };
  const cov = st.latest?.coverage;
  return (
    <>
      <div className="split ada-split">
        <div className="card">
          <div className="card-head"><h2>Сброс без последующей смены пользователем</h2><span className={`badge ${pending.total ? "err" : "ok"}`}>{pending.initial ? "…" : num(pending.total)}</span><div className="spacer" />
            <button className="btn mini" onClick={() => report({ title: "Сброс пароля (Reset Password)", params: { view: "resets" } })}><Icon name="file" size={15} />Отчёт</button></div>
          <p className="muted small">Штатный порядок — пользователь сам меняет пароль (Change Password, событие 4723). Сброс другой учётной записью (Reset Password, 4724) требует проверки, особенно если после него пользователь пароль не сменил.</p>
          {pending.initial ? <SkelRows rows={2} cols={3} /> : !pending.items.length ? <p className="small">{Object.keys(cov?.logs ?? {}).length ? "Таких учётных записей нет." : "Не определяется: журналы контроллеров не загружены."}</p> : (
            <div className="table-scroll"><table className="table compact"><thead><tr><th>Учётная запись</th><th>Основание</th><th>Решение</th></tr></thead>
              <tbody>{pending.items.map((f) => <tr key={f.key} className="row-bad"><td><button type="button" className="link-btn strong-link" onClick={() => onOpen(f.guid)}>{f.login}</button><span className="sub">{f.name}</span></td><td className="small">{f.basis}</td><td><DecisionBadge d={f.decision} /></td></tr>)}</tbody></table></div>)}
        </div>
        <div className="card">
          <div className="card-head"><h2>Журналы контроллеров</h2></div>
          {cov?.dcs?.length ? <ul className="ada-dcs">{cov.dcs.map((d) => { const l = cov.logs?.[d] ?? cov.logs?.[d.split(".")[0]]; return (
            <li key={d}><span className={`dot ${l ? "ok" : "bad"}`} aria-hidden /><span className="mono small">{d}</span><span className="muted small">{l ? `журнал ${fmtDate(l[0])} — ${fmtDate(l[1])}` : "журнала нет"}</span></li>); })}</ul> : <p className="muted small">Контроллеры домена не определены.</p>}
          <p className="small">LDAP не хранит историю операций с паролем: события читаются из журналов Security контроллеров скриптом <span className="mono">scripts/windows/Export-KavPasswordEvents.ps1</span> от учётной записи из группы «Event Log Readers» (права администратора домена не нужны) и загружаются сюда.</p>
          <label className={`btn ${busy ? "" : "primary"} mini ada-upload`} aria-busy={busy}><Icon name="upload" size={15} />Загрузить журналы (JSON)<input type="file" accept=".json,application/json" onChange={(e) => { void upload(e.target.files?.[0]); e.target.value = ""; }} /></label>
          {st.import && <p className="muted small">Последняя загрузка {fmt(st.import.at)} ({st.import.by}): «{st.import.file_name}», новых событий {num(st.import.added)}.</p>}
        </div>
      </div>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Учётная запись или инициатор", label: "Поиск событий" }}
        primary={<Segmented label="Вид операции" value={kind} onChange={setKind} options={[["reset", "Сброс (4724)"], ["change", "Смена (4723)"], ["", "Все"]]} />}
        count={{ n: evs.initial ? null : evs.total, noun: ["событие", "события", "событий"] }} onRefresh={() => evs.reload()} refreshing={evs.refreshing} />
      <div className="table-scroll">{evs.initial ? <SkelRows cols={5} /> : !evs.items.length ? <Empty icon="history" title="Событий нет">{st.import ? "Под условия отбора событий нет." : "Журналы контроллеров ещё не загружены."}</Empty> : (
        <table className="table"><thead><tr><th>Время</th><th>Операция</th><th>Учётная запись</th><th>Кто выполнил</th><th className="hide-sm">Контроллер</th><th>Результат</th></tr></thead>
          <tbody>{evs.items.map((e, i) => (
            <tr key={i} className={e.kind === "reset" && e.success ? "row-bad" : ""}><td className="small nowrap">{fmt(e.at)}</td><td>{e.kind === "reset" ? <span className="badge err">Сброс</span> : <span className="badge ok">Смена</span>}<span className="sub small muted">{e.event_id}</span></td>
              <td>{e.target_guid ? <button type="button" className="link-btn strong-link" onClick={() => onOpen(e.target_guid)}>{e.target}</button> : e.target}{e.target_name && <span className="sub">{e.target_name}</span>}</td>
              <td className="small">{e.by || "—"}</td><td className="small mono hide-sm">{e.dc}</td><td>{e.success ? "успешно" : <span className="warn-text">отказ</span>}</td></tr>))}</tbody></table>)}</div>
      <ListFoot list={evs} />
      {toast}
    </>
  );
}

function RunsView({ current, onPick }: { current: string; onPick: (id: string) => void }) {
  const [rows, setRows] = useState<AdRun[] | null>(null);
  useEffect(() => { api.adaudit.runs().then((r) => setRows(r.items)).catch(() => setRows([])); }, []);
  if (!rows) return <div className="card"><SkelRows rows={4} cols={6} /></div>;
  return (
    <div className="table-scroll"><table className="table">
      <thead><tr><th>Проверка</th><th>Вид</th><th>Состояние</th><th className="num">Учётных записей</th><th className="num">Замечаний</th><th className="num hide-sm">Новых</th><th className="num hide-sm">Устранено</th><th className="hide-md">Запустил</th></tr></thead>
      <tbody>{rows.map((r) => { const s = r.stats as Record<string, number>; return (
        <tr key={r.id} className={r.id === current ? "sel" : ""}>
          <td>{r.status === "ok" ? <button type="button" className="link-btn strong-link" onClick={() => onPick(r.id)}>{fmt(r.started_at)}</button> : fmt(r.started_at)}</td><td className="small">{r.kind_ru}</td>
          <td>{r.status === "ok" ? <span className="badge ok">выполнена</span> : r.status === "running" ? <span className="badge accent">выполняется</span> : <span className="badge err" title={r.message}>ошибка</span>}{r.status === "failed" && <span className="sub small">{r.message}</span>}</td>
          <td className="num">{s.accounts !== undefined ? num(s.accounts) : "—"}</td><td className="num">{s.findings !== undefined ? num(s.findings) : "—"}</td>
          <td className="num hide-sm">{s.new_since_prev !== undefined ? num(s.new_since_prev) : "—"}</td><td className="num hide-sm">{s.fixed_since_prev !== undefined ? num(s.fixed_since_prev) : "—"}</td><td className="small hide-md">{r.by || "по расписанию"}</td>
        </tr>); })}</tbody>
    </table></div>
  );
}

/** Карточка учётной записи: выводы сверху (категория, состояние, замечания с решениями), подробности — ниже: пароль, вход, привилегии, события, история по проверкам. */
function AccountPanel({ guid, run, onClose, onChanged }: { guid: string; run: string; onClose: () => void; onChanged: () => void }) {
  const [c, setC] = useState<AdAccountCard | null>(null); const [err, setErr] = useState("");
  const [deciding, setDeciding] = useState<AdFinding | null>(null);
  const [catEdit, setCatEdit] = useState(false); const [newCat, setNewCat] = useState<AdCategory | "">(""); const [note, setNote] = useState("");
  const [toast, show] = useToast();
  const load = useCallback(() => api.adaudit.account(guid, run || undefined).then(setC).catch((e) => setErr((e as ApiError).message)), [guid, run]);
  useEffect(() => { setC(null); void load(); }, [load]);
  const saveCat = async (cat: AdCategory | null) => { try { await api.adaudit.category(guid, cat, note); show(cat ? "Категория назначена: применится со следующей проверки" : "Категория снова определяется правилами"); setCatEdit(false); void load(); } catch (e) { show((e as ApiError).message, "error"); } };
  const op = c?.pwd_op;
  const kv = useMemo(() => c && [
    ["Категория", <>{c.category_ru}{c.override && <span className="sub small">назначена вручную: {c.override.by}, {fmtDate(c.override.at)}{c.override.note ? ` — ${c.override.note}` : ""}</span>}<span className="sub small muted">{c.category_basis.join("; ")}</span></>],
    ["Пароль изменён", c.must_change ? <span className="warn-text">не задан пользователем: сменить при следующем входе</span> : c.pwd_last_set ? <>{fmt(c.pwd_last_set)} <span className="muted">({days(c.pwd_age)})</span></> : "неизвестно"],
    ["Срок пароля", <>{c.pne ? <span className="badge err">бессрочный (Password Never Expires)</span> : "ограничен политикой"}{c.pwd_expired && <span className="sub warn-text">срок истёк</span>}</>],
    ["Последняя операция с паролем", op ? <><b className={op.state === "reset" && op.reset_pending ? "bad-text" : ""}>{OP_RU[op.state]}</b>{op.by && <span className="sub small">{op.by}{op.dc ? ` на ${op.dc}` : ""}</span>}<span className="sub small muted">{op.basis}</span></> : "—"],
    ["Последний вход", <>{c.last_logon ? <>{fmt(c.last_logon)} <span className="muted">({days(c.idle_days)} назад)</span></> : "не зафиксирован"}<span className="sub small muted">{SRC_RU[c.last_logon_src]}</span></>],
    ["Создана", c.created ? fmt(c.created) : "—"], ["Срок действия", c.expires ? fmtDate(c.expires) : "не ограничен"],
    ["Привилегированные группы", c.privileged.length ? c.privileged.join(", ") : "нет"], ["Protected Users", c.protected === null ? "не проверялось" : c.protected ? "входит" : "не входит"],
    ["Описание", c.description || <span className="muted">пусто</span>], ["Ответственный (manager)", c.manager || <span className="muted">не указан</span>],
    ["Подразделение, должность", [c.department, c.title].filter(Boolean).join(", ") || "—"], ["Вход разрешён на компьютерах", c.workstations || <span className="muted">не ограничено атрибутом</span>],
    ["Группы", c.groups.length ? <CompactList items={c.groups} max={8} label="группы" /> : "—"], ["DN", <span className="mono small">{c.dn}</span>],
  ] as [string, React.ReactNode][], [c, op]);
  return (
    <Modal side wide title={c?.login ?? "Учётная запись"} lede={c ? `${c.name}${c.upn ? ` · ${c.upn}` : ""}` : undefined} onClose={onClose}>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!c && !err && <SkelRows rows={6} cols={2} />}
      {c && <div className="ada-card">
        <div className="vdb-badges"><span className="badge accent">{c.category_ru}</span>{!c.enabled ? <span className="badge">отключена</span> : c.locked ? <span className="badge warn">заблокирована</span> : <span className="badge ok">активна</span>}
          {c.spn && <span className="badge">есть SPN</span>}<span className="muted small">по проверке от {fmtDate(c.run.started_at)}</span>
          <div className="spacer" /><button type="button" className="btn mini ghost" onClick={() => { setCatEdit(!catEdit); setNewCat(c.override?.category ?? ""); setNote(c.override?.note ?? ""); }}>Изменить категорию</button></div>
        {catEdit && <div className="ada-decide">
          <Segmented label="Категория" value={newCat as AdCategory} onChange={(v) => setNewCat(v)} options={(["user", "admin", "service", "temp", "contractor"] as AdCategory[]).map((k) => [k, CAT_RU[k]] as [AdCategory, string])} />
          <label>Основание<input value={note} onChange={(e) => setNote(e.target.value)} maxLength={300} placeholder="например, заявка или служебная записка" /></label>
          <div className="row">{c.override && <button type="button" className="btn ghost" onClick={() => void saveCat(null)}>Вернуть определение по правилам</button>}<div className="spacer" /><button type="button" className="btn primary" disabled={!newCat} onClick={() => void saveCat(newCat as AdCategory)}>Сохранить</button></div></div>}
        <h3 className="vdb-h">Замечания ({c.findings.length})</h3>
        {!c.findings.length ? <p className="muted small">Замечаний нет.</p> : <ul className="ada-cf">{c.findings.map((f) => (
          <li key={f.key} className={f.code === "reset" ? "bad" : ""}>
            <div className="row"><SevBadge s={f.severity} /><b>{f.title}</b>{f.status === "review" && <span className="badge">требует проверки</span>}<div className="spacer" /><DecisionBadge d={f.decision} />
              <button type="button" className="btn mini" onClick={() => setDeciding(deciding?.key === f.key ? null : f)}>Решение</button></div>
            <p className="small">{f.basis}</p>
            <p className="muted small">Впервые обнаружено {fmtDate(f.first_seen)}{f.runs_n > 1 ? `, ${f.runs_n}-я проверка подряд` : ""}{f.decision?.comment ? ` · ${f.decision.comment}` : ""}</p>
            {deciding?.key === f.key && <DecisionForm keys={[f.key]} init={f.decision} onCancel={() => setDeciding(null)} onDone={() => { setDeciding(null); void load(); onChanged(); }} />}
          </li>))}</ul>}
        <h3 className="vdb-h">Сведения</h3>
        <dl className="kv">{kv?.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>
        <h3 className="vdb-h">Смена и сброс пароля по журналам ({c.events.length})</h3>
        {!c.events.length ? <p className="muted small">Событий 4723/4724 по этой учётной записи в загруженных журналах нет.</p> : (
          <div className="table-scroll"><table className="table compact"><thead><tr><th>Время</th><th>Операция</th><th>Кто</th><th>Результат</th></tr></thead>
            <tbody>{c.events.map((e, i) => <tr key={i} className={e.kind === "reset" && e.success ? "row-bad" : ""}><td className="nowrap small">{fmt(e.at)}</td><td className="small">{e.kind_ru}</td><td className="small">{e.by}<span className="sub mono small">{e.dc}</span></td><td className="small">{e.success ? "успешно" : "отказ"}</td></tr>)}</tbody></table></div>)}
        <h3 className="vdb-h">По проверкам</h3>
        <div className="table-scroll"><table className="table compact"><thead><tr><th>Проверка</th><th>Категория</th><th>Пароль изменён</th><th>Последний вход</th><th className="num">Замечаний</th></tr></thead>
          <tbody>{c.history.map((h, i) => <tr key={i}><td className="small nowrap">{fmtDate(h.at)}<span className="sub small muted">{h.kind_ru}</span></td><td className="small">{h.category_ru}{!h.enabled && <span className="sub small muted">отключена</span>}</td>
            <td className="small nowrap">{fmtDate(h.pwd_last_set) || "—"}</td><td className="small nowrap">{fmtDate(h.last_logon) || "—"}</td><td className="num">{h.findings}</td></tr>)}</tbody></table></div>
      </div>}
      {toast}
    </Modal>
  );
}


