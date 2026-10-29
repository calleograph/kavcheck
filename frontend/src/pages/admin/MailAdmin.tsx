import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, type ApiError, type OutboxRow, type Schedule, type SourceRef, type ZoneBrief } from "../../api";
import { SecretInput, secretToSend } from "../../components/Common";
import { ConfirmDialog, Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { ListFoot, useInfinite, type Chunk } from "../../components/Infinite";
import { Empty, Segmented, SkelRows, Tabs } from "../../components/ui";
import { fmt, num } from "../../util";
import { DEFAULT_ZONE_CATS, ZONE_CATEGORIES } from "../zoneCats";

const WEEKDAYS = ["Понедельник", "Вторник", "Среда", "Четверг", "Пятница", "Суббота", "Воскресенье"];
const STATUS: Record<OutboxRow["status"], [string, string]> = { queued: ["в очереди", "accent"], sending: ["отправляется", "accent"], accepted: ["принято сервером", "ok"], failed: ["не отправлено", "err"], skipped: ["пропущено", "outline"] };

export default function MailAdmin({ sources }: { sources: SourceRef[] }) {
  const [tab, setTab] = useState<"schedules" | "history" | "smtp">("schedules");
  const [sum, setSum] = useState<Awaited<ReturnType<typeof api.admin.mail.summary>> | null>(null);
  useEffect(() => { api.admin.mail.summary().then(setSum).catch(() => setSum(null)); }, [tab]);
  const failed = sum?.counts_30d.failed ?? 0;
  return (
    <div className="stack">
      {sum && !sum.smtp_ready && <div className="alert warn"><Icon name="alert" /><div className="alert-body">Отправка почты не настроена: расписания создаются, но письма не уйдут, пока на вкладке «Подключение SMTP» не указан сервер и отправка не включена. <button className="link-btn" onClick={() => setTab("smtp")}>Настроить</button></div></div>}
      {failed > 0 && <div className="alert error"><Icon name="alert" /><div className="alert-body">Не отправлено отчётов за 30 суток: <b>{failed}</b>. <button className="link-btn" onClick={() => setTab("history")}>Открыть историю</button></div></div>}
      <Tabs label="Рассылки" value={tab} onChange={setTab} items={[{ id: "schedules", label: "Расписания" }, { id: "history", label: "История отправок", count: sum ? Object.values(sum.counts_30d).reduce((a, b) => a + b, 0) : undefined }, { id: "smtp", label: "Подключение SMTP" }]} />
      {tab === "schedules" && <Schedules sources={sources} next={sum?.next_run_at ?? null} />}
      {tab === "history" && <History />}
      {tab === "smtp" && <Smtp />}
    </div>
  );
}

// ------------------------------------------------------------------------------------------------ SMTP
const TXT = ["host", "port", "security", "username", "from_addr", "from_name", "timeout_s", "max_attach_mb", "retry_max", "retry_minutes", "alert_email", "base_url", "verify_cert", "enabled"] as const;
function Smtp() {
  const [v, setV] = useState<Record<string, string | number | boolean> | null>(null); const [base, setBase] = useState("");
  const [pw, setPw] = useState(""); const [pwSet, setPwSet] = useState(false);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [chk, setChk] = useState<{ ok: boolean; error: string } | null>(null); const [to, setTo] = useState(""); const [tst, setTst] = useState<{ ok: boolean; error: string; note: string } | null>(null); const [wait, setWait] = useState("");
  const [toast, show] = useToast();
  const load = useCallback(() => api.admin.settings("smtp").then((x) => { const { password_set, ...rest } = x as Record<string, string | number | boolean>; setV(rest); setBase(JSON.stringify(rest)); setPwSet(!!password_set); setPw(""); }).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); }, [load]);
  if (!v) return <div className="card">{err ? <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div> : <SkelRows rows={4} cols={2} />}</div>;
  const set = (k: string, x: string | number | boolean) => setV({ ...v, [k]: x });
  const dirty = base !== JSON.stringify(v) || pw !== "";
  const save = async (e: FormEvent) => {
    e.preventDefault(); setErr(""); setBusy(true);
    try { const body: Record<string, string | number | boolean | null> = Object.fromEntries(TXT.map((k) => [k, v[k]])); const p = secretToSend(pw); if (pw === " ") body.password = ""; else if (p !== undefined) body.password = p; await api.admin.saveSettings("smtp", body); await load(); show("Настройки почты сохранены"); }
    catch (y) { setErr((y as ApiError).message); } finally { setBusy(false); }
  };
  const check = async () => { setWait("check"); setChk(null); try { setChk(await api.admin.mail.check()); } catch (e) { setChk({ ok: false, error: (e as ApiError).message }); } finally { setWait(""); } };
  const test = async () => { setWait("test"); setTst(null); try { setTst(await api.admin.mail.test(to.trim())); } catch (e) { setTst({ ok: false, error: (e as ApiError).message, note: "" }); } finally { setWait(""); } };
  return (
    <form className="card form" onSubmit={save}>
      <h2>Подключение к серверу SMTP</h2>
      <p className="muted small lead-in">Через него уходят отчёты ответственным. Пароль хранится зашифрованным и не показывается. Сохраните настройки, затем проверьте подключение и отправьте тестовое письмо.</p>
      <label className="check"><input type="checkbox" className="switch" checked={!!v.enabled} onChange={(e) => set("enabled", e.target.checked)} />Отправка почты включена</label>
      <div className="cols"><label>Сервер<input value={String(v.host)} onChange={(e) => set("host", e.target.value)} placeholder="smtp.example.local" /></label><label>Порт<input type="number" min={1} max={65535} value={Number(v.port)} onChange={(e) => set("port", Number(e.target.value))} /></label></div>
      <div className="field">Шифрование<Segmented label="Шифрование" value={String(v.security)} onChange={(x) => { set("security", x); if (x === "ssl" && Number(v.port) === 587) set("port", 465); if (x === "starttls" && Number(v.port) === 465) set("port", 587); }}
        options={[["starttls", "STARTTLS (587)"], ["ssl", "TLS сразу (465)"], ["none", "Без шифрования"]]} />{v.security === "none" && <span className="help warn-text">Пароль и отчёты пойдут открытым текстом. Используйте только во внутренней сети.</span>}</div>
      <div className="cols"><label>Пользователь<input value={String(v.username)} onChange={(e) => set("username", e.target.value)} autoComplete="off" /><span className="help">Пусто — без проверки подлинности.</span></label>
        <SecretInput label="Пароль" isSet={pwSet} value={pw} onChange={setPw} help="Только символы ASCII (ограничение протокола SMTP AUTH в стандартной библиотеке)." /></div>
      <div className="cols"><label>Адрес отправителя<input type="email" value={String(v.from_addr)} onChange={(e) => set("from_addr", e.target.value)} placeholder="kav-checker@example.local" /></label><label>Имя отправителя<input value={String(v.from_name)} onChange={(e) => set("from_name", e.target.value)} /></label></div>
      <label className="check"><input type="checkbox" className="switch" checked={!!v.verify_cert} onChange={(e) => set("verify_cert", e.target.checked)} />Проверять сертификат сервера <span className="muted small">(отключайте только для внутреннего сертификата без цепочки доверия)</span></label>
      <div className="cols"><label>Адрес KAV Checker для ссылок в письмах<input value={String(v.base_url)} onChange={(e) => set("base_url", e.target.value)} placeholder="https://kav.example.local" /><span className="help">Получатель открывает отчёт через авторизованный интерфейс. Пусто — без ссылок.</span></label>
        <label>Кому сообщать о недоставленных отчётах<input type="email" value={String(v.alert_email)} onChange={(e) => set("alert_email", e.target.value)} placeholder="ib@example.local" /></label></div>
      <div className="cols"><label>Предел вложений, МБ<input type="number" min={1} max={50} value={Number(v.max_attach_mb)} onChange={(e) => set("max_attach_mb", Number(e.target.value))} /><span className="help">Больше — письмо уходит со сводкой и ссылкой, без файла.</span></label>
        <label>Попыток отправки<input type="number" min={1} max={20} value={Number(v.retry_max)} onChange={(e) => set("retry_max", Number(e.target.value))} /></label>
        <label>Пауза перед повтором, мин<input type="number" min={1} max={1440} value={Number(v.retry_minutes)} onChange={(e) => set("retry_minutes", Number(e.target.value))} /><span className="help">Дальше удваивается.</span></label></div>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="form-actions"><button className="btn primary" aria-busy={busy} disabled={!dirty}><span>Сохранить</span></button>{dirty && <span className="badge warn">есть несохранённые изменения</span>}</div>
      <hr />
      <h3>Проверка</h3>
      <div className="row"><button type="button" className="btn" onClick={check} disabled={!!wait || dirty} aria-busy={wait === "check"}><Icon name="plug" />Проверить подключение</button>
        {chk && <span className={`badge ${chk.ok ? "ok" : "err"}`}>{chk.ok ? "подключение и вход успешны" : chk.error}</span>}</div>
      <div className="row"><input className="w-md" type="email" value={to} onChange={(e) => setTo(e.target.value)} placeholder="адрес для тестового письма" aria-label="Адрес для тестового письма" />
        <button type="button" className="btn" onClick={test} disabled={!!wait || dirty || !to.includes("@")} aria-busy={wait === "test"}><Icon name="mail" />Отправить тестовое письмо</button></div>
      {tst && <div className={`alert ${tst.ok ? "ok" : "error"}`} role="status"><Icon name={tst.ok ? "checkCircle" : "alert"} /><div className="alert-body">{tst.ok ? `Сервер принял письмо. ${tst.note}` : tst.error}</div></div>}
      {dirty && <p className="muted small">Проверка использует сохранённые настройки: сначала нажмите «Сохранить».</p>}
      {toast}
    </form>
  );
}

// ------------------------------------------------------------------------------------------------ расписания
function Schedules({ sources, next }: { sources: SourceRef[]; next: string | null }) {
  const [items, setItems] = useState<Schedule[] | null>(null); const [zones, setZones] = useState<ZoneBrief[]>([]); const [err, setErr] = useState("");
  const [edit, setEdit] = useState<Schedule | "new" | null>(null); const [del, setDel] = useState<Schedule | null>(null); const [run, setRun] = useState<Schedule | null>(null);
  const [toast, show] = useToast();
  const load = useCallback(() => { api.admin.mail.schedules().then((r) => setItems(r.items)).catch((e) => setErr((e as ApiError).message)); }, []);
  useEffect(() => { load(); api.admin.zones.list().then((r) => setZones(r.items)).catch(() => undefined); }, [load]);
  const toggle = async (s: Schedule) => { try { await api.admin.mail.toggleSchedule(s.id, !s.enabled); load(); show(s.enabled ? "Расписание отключено" : "Расписание включено"); } catch (e) { setErr((e as ApiError).message); } };
  return (<>
    <div className="toolbar"><span className="muted small">{next ? `Ближайшая отправка: ${fmt(next)}` : "Включённых расписаний нет"}</span><div className="spacer" /><button className="btn primary" onClick={() => setEdit("new")}><Icon name="plus" />Создать расписание</button></div>
    {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
    <div className="table-scroll">{!items ? <SkelRows cols={6} /> : !items.length ? (
      <Empty icon="mail" title="Рассылок ещё нет" action={<button className="btn primary" onClick={() => setEdit("new")}><Icon name="plus" />Создать расписание</button>}>Типичный сценарий: каждый понедельник в 08:00 каждый ответственный получает письмо со сводкой по своим компьютерам и подробным отчётом во вложении.</Empty>
    ) : (
      <table className="table"><thead><tr><th>Расписание</th><th>Зоны</th><th>Когда</th><th>Содержание</th><th>Следующая</th><th>Последняя</th><th /></tr></thead>
        <tbody>{items.map((s) => (
          <tr key={s.id} className={s.enabled ? "" : "dim-row"}><td><button className="link-btn strong-link" onClick={() => setEdit(s)}>{s.name}</button>{!s.enabled && <span className="badge outline"> отключено</span>}<span className="sub">{s.level_ru}</span></td>
            <td className="small">{s.all_zones ? "Все зоны" : s.zone_names.slice(0, 3).join(", ") + (s.zone_names.length > 3 ? ` и ещё ${s.zone_names.length - 3}` : "")}{s.include_unassigned ? <span className="sub">+ «Без ответственного» администратору</span> : null}</td>
            <td className="small">{s.when}</td><td className="small">{s.sections_ru.slice(0, 2).join("; ")}{s.sections_ru.length > 2 ? ` и ещё ${s.sections_ru.length - 2}` : ""}<span className="sub">{[s.attach_html && "HTML", s.attach_xlsx && "Excel", s.skip_empty && "не слать, если проблем нет"].filter(Boolean).join(", ")}</span></td>
            <td className="small nowrap">{s.enabled ? fmt(s.next_run_at) : "—"}</td><td className="small nowrap">{s.last_run_at ? fmt(s.last_run_at) : "—"}<span className="sub">{s.last_period}</span></td>
            <td className="nowrap"><button className="btn mini" onClick={() => setRun(s)}><Icon name="play" size={14} />Отправить сейчас</button> <button className="btn mini ghost" onClick={() => toggle(s)}>{s.enabled ? "Отключить" : "Включить"}</button> <button className="btn mini ghost icon" aria-label={`Удалить ${s.name}`} onClick={() => setDel(s)}><Icon name="trash" size={15} /></button></td></tr>))}</tbody></table>)}</div>
    {edit && <ScheduleEditor s={edit === "new" ? null : edit} zones={zones} sources={sources} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); load(); show("Расписание сохранено"); }} />}
    {run && <RunNow s={run} zones={zones} onClose={() => setRun(null)} onDone={(m) => { setRun(null); show(m); }} />}
    {del && <ConfirmDialog title={`Удалить расписание «${del.name}»?`} body="История отправок сохранится." confirmLabel="Удалить" onConfirm={async () => { await api.admin.mail.deleteSchedule(del.id); load(); show("Расписание удалено"); }} onClose={() => setDel(null)} />}
    {toast}
  </>);
}

function RunNow({ s, zones, onClose, onDone }: { s: Schedule; zones: ZoneBrief[]; onClose: () => void; onDone: (m: string) => void }) {
  const pool = s.all_zones ? zones : zones.filter((z) => s.zone_ids.includes(z.id));
  const [pick, setPick] = useState<string[]>([]); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const go = async () => { setBusy(true); try { const r = await api.admin.mail.runSchedule(s.id, pick); onDone(`В очередь поставлено писем: ${r.queued}${r.skipped ? `, пропущено (нет получателей): ${r.skipped}` : ""}. Отправка начнётся в течение минуты.`); } catch (e) { setErr((e as ApiError).message); setBusy(false); } };
  return <Modal title={`Отправить сейчас: ${s.name}`} onClose={onClose} guard={false} lede="Письма уйдут получателям выбранных зон по правилам этого расписания. Плановые отправки не сдвигаются."
    footer={<><button className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" onClick={go} disabled={busy} aria-busy={busy}><span>Отправить{pick.length ? ` (${pick.length})` : " всем зонам"}</span></button></>}>
    <div className="check-grid">{pool.map((z) => <label key={z.id} className="check"><input type="checkbox" checked={pick.includes(z.id)} onChange={() => setPick(pick.includes(z.id) ? pick.filter((x) => x !== z.id) : [...pick, z.id])} />{z.name}{z.contacts ? "" : <span className="warn-text small"> нет получателей</span>}</label>)}</div>
    <p className="muted small">Если ничего не выбрать, письмо получат все зоны расписания.</p>{err && <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>}</Modal>;
}

function ScheduleEditor({ s, zones, sources, onClose, onSaved }: { s: Schedule | null; zones: ZoneBrief[]; sources: SourceRef[]; onClose: () => void; onSaved: () => void }) {
  const [tz, setTz] = useState("UTC");
  useEffect(() => { api.admin.settings("general").then((g) => { if (!s) setF((x) => ({ ...x, tz: String(g.timezone || "UTC") })); setTz(String(g.timezone || "UTC")); }).catch(() => undefined); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const [f, setF] = useState(() => ({ name: s?.name ?? "Еженедельная сводка", enabled: s?.enabled ?? true, zone_ids: s?.zone_ids ?? [], all: s ? s.all_zones : true, include_unassigned: s?.include_unassigned ?? false, sections: s?.sections ?? DEFAULT_ZONE_CATS,
    level: s?.level ?? "management", frequency: s?.frequency ?? "weekly", weekday: s?.weekday ?? 0, monthday: s?.monthday ?? 1, at_time: s?.at_time ?? "08:00", tz, attach_html: s?.attach_html ?? true, attach_xlsx: s?.attach_xlsx ?? false,
    skip_empty: s?.skip_empty ?? false, severity: String(s?.filters.severity ?? ""), online_only: !!s?.filters.online_only, include_inactive: !!s?.filters.include_inactive, show_excluded: !!s?.filters.show_excluded, source_ids: (s?.filters.source_ids as string[] | undefined) ?? [] }));
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const set = <K extends keyof typeof f>(k: K, v: (typeof f)[K]) => setF((x) => ({ ...x, [k]: v }));
  const toggle = (k: "zone_ids" | "sections" | "source_ids", id: string) => set(k, (f[k] as string[]).includes(id) ? (f[k] as string[]).filter((x) => x !== id) : [...(f[k] as string[]), id]);
  const save = async () => {
    setBusy(true); setErr("");
    const body = { name: f.name, enabled: f.enabled, zone_ids: f.all ? [] : f.zone_ids, include_unassigned: f.include_unassigned, sections: f.sections, level: f.level, frequency: f.frequency, weekday: f.weekday, monthday: f.monthday, at_time: f.at_time, tz: f.tz,
      attach_html: f.attach_html, attach_xlsx: f.attach_xlsx, skip_empty: f.skip_empty, filters: { severity: f.severity, online_only: f.online_only, include_inactive: f.include_inactive, show_excluded: f.show_excluded, source_ids: f.source_ids } };
    try { if (s) await api.admin.mail.updateSchedule(s.id, body); else await api.admin.mail.createSchedule(body); onSaved(); } catch (e) { setErr((e as ApiError).message); setBusy(false); }
  };
  return (
    <Modal wide title={s ? `Расписание: ${s.name}` : "Новое расписание"} onClose={onClose} lede="Каждая зона получает своё письмо: краткая сводка в теле и подробный отчёт во вложении. Данные других зон получатель не видит."
      footer={<><button className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" onClick={save} disabled={busy || !f.name.trim() || (!f.all && !f.zone_ids.length) || !f.sections.length} aria-busy={busy}><span>Сохранить</span></button></>}>
      <div className="form">
        <div className="cols"><label>Название<input value={f.name} onChange={(e) => set("name", e.target.value)} maxLength={160} /></label>
          <label className="check"><input type="checkbox" className="switch" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} />Расписание включено</label></div>
        <h3>Кому</h3>
        <label className="check"><input type="radio" name="all" checked={f.all} onChange={() => set("all", true)} />Всем зонам (включая созданные позже)</label>
        <label className="check"><input type="radio" name="all" checked={!f.all} onChange={() => set("all", false)} />Выбранным зонам</label>
        {!f.all && <div className="check-grid">{zones.map((z) => <label key={z.id} className="check"><input type="checkbox" checked={f.zone_ids.includes(z.id)} onChange={() => toggle("zone_ids", z.id)} />{z.name}{z.contacts ? "" : <span className="warn-text small"> нет получателей</span>}</label>)}</div>}
        <label className="check"><input type="checkbox" checked={f.include_unassigned} onChange={(e) => set("include_unassigned", e.target.checked)} />Отчёт по компьютерам «Без ответственного» — администратору (адрес для уведомлений из настроек SMTP)</label>
        <h3>Когда</h3>
        <div className="sched-grid">
          <label>Периодичность<select value={f.frequency} onChange={(e) => set("frequency", e.target.value as Schedule["frequency"])}><option value="daily">Каждый день</option><option value="weekly">Раз в неделю</option><option value="monthly">Раз в месяц</option></select></label>
          {f.frequency === "weekly" && <label>День недели<select value={f.weekday} onChange={(e) => set("weekday", Number(e.target.value))}>{WEEKDAYS.map((d, i) => <option key={i} value={i}>{d}</option>)}</select></label>}
          {f.frequency === "monthly" && <label>Число месяца<input type="number" min={1} max={31} value={f.monthday} onChange={(e) => set("monthday", Number(e.target.value))} /><span className="help">31 в коротком месяце — последний день.</span></label>}
          <label>Время<input type="time" value={f.at_time} onChange={(e) => set("at_time", e.target.value)} /></label>
          <label>Часовой пояс<input className="mono" value={f.tz} onChange={(e) => set("tz", e.target.value)} placeholder="Europe/Moscow" /></label>
        </div>
        <p className="muted small">Если сервер был выключен в момент отправки, после запуска уйдёт один отчёт за пропущенный период, а не все накопившиеся. Повторно один и тот же период не отправляется.</p>
        <h3>Что включить</h3>
        <div className="check-grid">{ZONE_CATEGORIES.map(([k, l]) => <label key={k} className="check"><input type="checkbox" checked={f.sections.includes(k)} onChange={() => toggle("sections", k)} />{l}</label>)}</div>
        <div className="sched-grid">
          <label>Подробность<select value={f.level} onChange={(e) => set("level", e.target.value as "management" | "technical")}><option value="management">Для руководства (сводка и список)</option><option value="technical">Для администраторов (с подробностями)</option></select></label>
          <label>Критичность уязвимостей<select value={f.severity} onChange={(e) => set("severity", e.target.value)}><option value="">Все уровни</option><option value="high">Высокие и критические</option><option value="critical">Только критические</option></select></label>
        </div>
        <label className="check"><input type="checkbox" checked={f.include_inactive} onChange={(e) => set("include_inactive", e.target.checked)} />Включать давно не подключавшиеся к KSC</label>
        <label className="check"><input type="checkbox" checked={f.online_only} onChange={(e) => set("online_only", e.target.checked)} />Только компьютеры, которые KSC видит в сети сейчас</label>
        <label className="check"><input type="checkbox" checked={f.show_excluded} onChange={(e) => set("show_excluded", e.target.checked)} />Перечислять исключённые обнаружения (ложные срабатывания) с обоснованиями</label>
        {sources.length > 1 && <><h3>Источники KSC</h3><div className="check-grid">{sources.map((x) => <label key={x.id} className="check"><input type="checkbox" checked={f.source_ids.includes(x.id)} onChange={() => toggle("source_ids", x.id)} />{x.name}</label>)}</div><p className="muted small">Не выбрано — все источники.</p></>}
        <h3>Вложения</h3>
        <label className="check"><input type="checkbox" checked={f.attach_html} onChange={(e) => set("attach_html", e.target.checked)} />Отчёт HTML (открывается без подключения, печатается в PDF)</label>
        <label className="check"><input type="checkbox" checked={f.attach_xlsx} onChange={(e) => set("attach_xlsx", e.target.checked)} />Отчёт Excel</label>
        <label className="check"><input type="checkbox" checked={f.skip_empty} onChange={(e) => set("skip_empty", e.target.checked)} />Не отправлять зоне, у которой нет проблем</label>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      </div>
    </Modal>
  );
}

// ------------------------------------------------------------------------------------------------ история
function History() {
  const [status, setStatus] = useState(""); const [q, setQ] = useState("");

  const [toast, show] = useToast();
  const [err, setErr] = useState(""); const [tick, setTick] = useState(0);
  const [aq, setAq] = useState(q);
  useEffect(() => { const t = window.setTimeout(() => setAq(q), 250); return () => window.clearTimeout(t); }, [q]);
  const list = useInfinite<OutboxRow>("mail:outbox", [status, aq, tick], (offset, limit) => api.admin.mail.outbox({ status, q: aq, offset, limit }) as unknown as Promise<Chunk<OutboxRow>>, 50);
  const data = list.initial ? null : { items: list.items, total: list.total, counts: (list.extra?.counts ?? {}) as Record<string, number> };
  useEffect(() => { if (!data?.items.some((r) => r.status === "queued" || r.status === "sending")) return; const t = window.setInterval(() => setTick((x) => x + 1), 5000); return () => window.clearInterval(t); }, [data]);
  const retry = async (r: OutboxRow) => { try { await api.admin.mail.retry(r.id); show("Отправка поставлена в очередь повторно"); setTick(tick + 1); } catch (e) { setErr((e as ApiError).message); } };
  const c = data?.counts ?? {};
  return (<>
    <div className="toolbar"><div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Зона, тема, адрес, ошибка" aria-label="Поиск" /></div>
      <Segmented label="Статус" value={status} onChange={setStatus} options={[["", "Все"], ["accepted", `Принято ${c.accepted ?? 0}`], ["queued", `В очереди ${c.queued ?? 0}`], ["failed", `Не отправлено ${c.failed ?? 0}`], ["skipped", `Пропущено ${c.skipped ?? 0}`]]} /></div>
    {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
    <div className="table-scroll">{!data ? <SkelRows cols={6} /> : !data.items.length ? <Empty icon="mail" title="Отправок пока не было">Здесь появятся плановые и ручные отправки: когда сформирован отчёт, кому направлен и принял ли его сервер почты.</Empty> : (
      <table className="table compact"><thead><tr><th>Сформировано</th><th>Зона и период</th><th>Кому</th><th>Статус</th><th>Попыток</th><th /></tr></thead>
        <tbody>{data.items.map((r) => (
          <tr key={r.id} className="row-in"><td className="nowrap small">{fmt(r.created_at)}{r.kind === "manual" && <span className="sub">вручную</span>}</td>
            <td>{r.zone_name || "—"}<span className="sub">{r.period_key.startsWith("manual") ? "вне расписания" : r.period_key}{r.stats?.problem_hosts !== undefined ? ` · проблемных: ${num(r.stats.problem_hosts)} из ${num(r.stats.total)}` : ""}</span></td>
            <td className="small">{r.to.join(", ") || "—"}{r.cc.length > 0 && <span className="sub">копия: {r.cc.join(", ")}</span>}{r.refused.length > 0 && <span className="sub warn-text">отклонены сервером: {r.refused.map((x) => x.address).join(", ")}</span>}</td>
            <td><span className={`badge ${STATUS[r.status][1]}`}>{STATUS[r.status][0]}</span>{r.status === "accepted" && <span className="sub">{fmt(r.sent_at)}</span>}{r.status === "queued" && r.next_attempt_at && <span className="sub">следующая попытка {fmt(r.next_attempt_at)}</span>}
              {r.last_error && <span className="sub bad-text" title={r.last_error}>{r.last_error.slice(0, 140)}</span>}</td>
            <td className="num">{r.attempts}</td><td>{(r.status === "failed" || r.status === "skipped") && <button className="btn mini" onClick={() => retry(r)}>Повторить</button>}</td></tr>))}</tbody></table>)}</div>
    <ListFoot list={list} />
    <p className="muted small">«Принято сервером» означает, что почтовый сервер принял письмо к отправке; это не подтверждает доставку и прочтение адресатом. Записи хранятся 180 суток.</p>
    {toast}
  </>);
}
