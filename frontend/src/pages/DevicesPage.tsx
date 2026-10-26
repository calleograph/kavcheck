import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type ApiError, type DevicesStatus, type DevUser, type DeviceCard, type DeviceRow } from "../api";
import { NoSource, type Ctx } from "../App";
import { CompactList } from "../components/CompactList";
import { Modal } from "../components/Dialogs";
import { EolBadge, EolDates, EolSev } from "../components/EolBits";
import { Icon } from "../components/Icons";
import { ListFoot, useInfinite, useKept } from "../components/Infinite";
import { useToast } from "../components/Toast";
import { ZoneField } from "../components/ZoneBits";
import { Empty, PageHead, Segmented, SkelRows, SortTh } from "../components/ui";
import { fmt, fmtDate, num, plural } from "../util";

const who = (u: DevUser) => (u.resolved ? (u.domain ? `${u.domain}\\${u.login}` : u.login) : "учётная запись не сопоставлена в KSC");
const KIND: Record<string, string> = { user: "", service: "служебная", system: "системная" };

/** Один пользователь: имя и пометка; «сейчас» выделено. */
function UserChip({ u }: { u: DevUser }) {
  return <span className={`user-chip ${u.now ? "now" : ""} ${u.resolved ? "" : "muted"}`} title={u.now ? "в списке вошедших при последнем опросе" : u.last_session_at ? `замечен в сеансе ${fmt(u.last_session_at)}` : "входил ранее; даты в KSC нет"}>
    {who(u)}{KIND[u.kind] ? <i> ({KIND[u.kind]})</i> : null}</span>;
}

/** Раздел «Устройства и пользователи»: единая таблица устройств с пользователями, зонами и EOL; поиск по имени, IP (адрес, сеть CIDR, диапазон, маска) и логину. */
export default function DevicesPage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const [q, setQ] = useKept("dev.q", ""); const [applied, setApplied] = useState(q);
  const [zone, setZone] = useKept("dev.zone", ""); const [eol, setEol] = useKept("dev.eol", ""); const [osq, setOsq] = useKept("dev.os", ""); const [uq, setUq] = useKept("dev.user", "");
  const [srcId, setSrcId] = useKept("dev.src", ""); const [all, setAll] = useKept("dev.all", false); const [service, setService] = useKept("dev.service", false);
  const [sort, setSort] = useKept("dev.sort", "name"); const [desc, setDesc] = useKept("dev.desc", false);
  const [status, setStatus] = useState<DevicesStatus | null>(null); const [toast, show] = useToast();
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 400); return () => window.clearTimeout(t); }, [q]);
  useEffect(() => { if (ctx.current) api.devices.status().then(setStatus).catch(() => setStatus(null)); }, [ctx.current, ctx.all]);
  const list = useInfinite<DeviceRow>(`dev:${ctx.current?.id}:${ctx.all}`, [applied, zone, eol, osq, uq, srcId, all, service, sort, desc],
    (offset, limit) => api.devices.list({ q: applied, zone, eol, os: osq, user: uq, source_id: ctx.all ? srcId : "", all_hosts: all || undefined, show_service: service || undefined, sort, desc, offset, limit }), 50);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const extra = list.extra as { limits?: string; not_ready?: string[] } | null;
  const multi = ctx.all;
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(false); } };
  const card = sp.get("card");
  const poll = async () => { try { const r = await api.devices.poll(); show(r.queued ? "Опрос поставлен в очередь: результат появится в течение минуты" : "Нет источников, которые отдают списки пользователей"); } catch (e) { show((e as ApiError).message, "error"); } };
  const bad = status?.items.filter((s) => !s.supported || s.error) ?? [];
  const canPoll = ctx.me.user.role !== "viewer";
  return (
    <section>
      <PageHead title="Устройства и пользователи" lede="Все устройства с пользователями, зонами ответственности и признаком EOL в одной таблице. Пользователи накапливаются по наблюдениям: KSC не хранит даты входа.">
        {canPoll && <button className="btn" onClick={poll}><Icon name="refresh" />Опросить пользователей</button>}
      </PageHead>
      {(extra?.not_ready?.length ?? 0) > 0 && <div className="alert info"><Icon name="info" /><div className="alert-body">Данные зон ещё не рассчитаны для: {extra!.not_ready!.join(", ")}. Устройства появятся после первого расчёта (Администрирование → Расчёт данных зон).</div></div>}
      {bad.map((s) => <div key={s.source_id} className="alert warn"><Icon name="alert" /><div className="alert-body">Источник «{s.source}»: {!s.supported ? "в базе KSC нет таблиц пользователей — столбцы пользователей пусты." : `опрос пользователей не удался (${s.error}). Показаны данные последнего успешного опроса${s.polled_at ? ` от ${fmt(s.polled_at)}` : ""}.`}</div></div>)}
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} aria-label="Поиск устройств" placeholder="Имя, логин или IP: srv-*, ivanov, 10.20.0.0/16, 10.1.2.5-40, 10.1.*  (несколько значений через пробел)" /></div>
        <Segmented<string> label="EOL" value={eol} onChange={setEol} options={[["", "Все"], ["any", "С проблемами поддержки"], ["eol", "С EOL"], ["none", "Без проблем"]]} />
        <details className="disclosure toolbar-more"><summary>Дополнительно</summary>
          <div className="toolbar-fields">
            <label className="field">ОС<input value={osq} onChange={(e) => setOsq(e.target.value)} placeholder="Windows 10*" className="w-md" /></label>
            <label className="field">Пользователь<input value={uq} onChange={(e) => setUq(e.target.value)} placeholder="логин" className="w-md" /></label>
            {ctx.all && <label className="field">Источник KSC<select value={srcId} onChange={(e) => setSrcId(e.target.value)}><option value="">Все</option>{ctx.sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>}
            <ZoneField value={zone} onChange={setZone} />
            <label className="check inline-check"><input type="checkbox" className="switch" checked={service} onChange={(e) => setService(e.target.checked)} />Показывать служебные и системные учётные записи</label>
          </div>
        </details>
        <div className="toolbar-foot"><span className="muted small">Адрес ищется по диапазону чисел, а не по тексту: сети CIDR, диапазоны и маски по октетам работают на любом числе устройств. Поиск по логину учитывает накопленные наблюдения.</span></div>
      </div>
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={7} /> : (
          <table className="table">
            <thead><tr><SortTh k="name" label="Устройство" sort={sort} desc={desc} onSort={onSort} /><SortTh k="ip" label="IP-адрес" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /><SortTh k="os" label="ОС" sort={sort} desc={desc} onSort={onSort} className="hide-md" />
              <th className="hide-md">Группа и зона</th><SortTh k="last_connected" label="Подключение к KSC" sort={sort} desc={desc} onSort={onSort} /><th>Пользователи</th><SortTh k="users" label="За 7 сут" sort={sort} desc={desc} onSort={onSort} className="num hide-sm" />
              <SortTh k="eol" label="EOL" sort={sort} desc={desc} onSort={onSort} className="num" />{multi && <th className="hide-sm">Источник</th>}</tr></thead>
            <tbody>
              {list.items.map((d) => (
                <tr key={`${d.source_id}:${d.host_id}`} className="clickable" onClick={(e) => { if (!(e.target as HTMLElement).closest("a, button")) setSp((p) => { p.set("card", `${d.source_id}:${d.host_id}`); return p; }); }}>
                  <td><button type="button" className="link-btn strong-link" onClick={() => setSp((p) => { p.set("card", `${d.source_id}:${d.host_id}`); return p; })}>{d.name}</button>{!d.active && <span className="badge">не активно</span>}</td>
                  <td className="mono small nowrap hide-sm">{d.ip || "—"}</td><td className="small hide-md">{d.os || "—"}</td>
                  <td className="small hide-md">{d.group || "—"}<span className="sub"><CompactList items={d.zones} label="зоны" /></span></td>
                  <td className="nowrap small">{fmt(d.last_connected)}</td>
                  <td className="small users-cell">
                    {d.current.length > 0 && <span className="block"><span className="muted">сейчас: </span><CompactList items={d.current} label="вошедшие сейчас" render={(u) => <UserChip u={u} />} /></span>}
                    {d.current.length === 0 && d.last_user && <span className="block"><span className="muted">последний замеченный: </span><UserChip u={d.last_user} />{d.last_user.last_session_at && <span className="sub small">наблюдение {fmt(d.last_user.last_session_at)}</span>}</span>}
                    {d.current.length === 0 && !d.last_user && (d.history.length > 0 ? <span className="block"><span className="muted">входили ранее (дат нет): </span><CompactList items={d.history} label="входившие ранее" render={(u) => <UserChip u={u} />} /></span> : <span className="muted">нет данных</span>)}
                  </td>
                  <td className="num hide-sm">{d.week_n ? <span title={d.week.map(who).join(", ")}>{num(d.week_n)}</span> : <span className="muted">—</span>}</td>
                  <td className="num">{d.eol ? <Link to={`/devices?card=${d.source_id}:${d.host_id}`} title={d.eol_level === "eol" ? "есть программа или ОС без поддержки производителя" : "есть проблемы поддержки"}>
                    <span className={`badge ${d.eol_level === "eol" ? "err" : "warn"}`}>{num(d.eol)}</span></Link> : <span className="muted">0</span>}</td>
                  {multi && <td className="small hide-sm">{d.source}</td>}
                </tr>))}
              {!list.items.length && !list.loading && <tr><td colSpan={9}><Empty icon="search" title="Устройства не найдены">{applied || zone || eol || osq || uq ? "Измените запрос или фильтры." : "Подготовленных данных зон ещё нет или нет активных устройств."}</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
      <p className="hidden-note"><Icon name={all ? "eye" : "eyeOff"} size={15} /><span>{all ? "Показаны все устройства, включая не подключавшиеся к KSC дольше срока активности." : "Показаны устройства со связью с KSC за период активности."}</span>
        <button type="button" className="link-btn" onClick={() => setAll(!all)}>{all ? "Скрыть неактивные" : "Показать все"}</button></p>
      {extra?.limits && <details className="disclosure"><summary>Что известно о пользователях и чего нет в KSC</summary><p className="small">{extra.limits}</p>
        {status && <ul className="small">{status.items.map((s) => <li key={s.source_id}>{s.source}: {s.polled_at ? `последний опрос ${fmt(s.polled_at)}` : "опроса ещё не было"}{s.first_poll_at ? `, наблюдения ведутся с ${fmtDate(s.first_poll_at)}` : ""}.</li>)}</ul>}</details>}
      {card && <CardModal id={card} service={service} onClose={() => setSp((p) => { p.delete("card"); return p; })} ctx={ctx} />}
      {toast}
    </section>
  );
}

function CardModal({ id, service, onClose, ctx }: { id: string; service: boolean; onClose: () => void; ctx: Ctx }) {
  const [sid, hid] = id.split(":");
  const [d, setD] = useState<DeviceCard | null>(null); const [err, setErr] = useState("");
  useEffect(() => { api.devices.card(sid, Number(hid), service).then(setD).catch((e) => setErr((e as ApiError).message)); }, [sid, hid, service]);
  return (
    <Modal side wide title={d?.name ?? "Устройство"} onClose={onClose} lede={d ? `${d.source} · ${d.ip || "адрес неизвестен"} · ${d.os || "ОС неизвестна"}` : undefined}>
      {err && <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!d && !err && <span className="spin accent" role="status" aria-label="Загрузка" />}
      {d && <>
        <dl className="kv">
          <div><dt>Группа администрирования</dt><dd>{d.group || "—"}</dd></div><div><dt>Зоны ответственности</dt><dd>{d.zones.length ? <CompactList items={d.zones} max={10} /> : "—"}</dd></div>
          <div><dt>Последнее подключение к KSC (UTC)</dt><dd>{fmt(d.last_connected)}{d.online !== null && <> · {d.online ? "в сети" : "не в сети"}</>}</dd></div>
        </dl>
        {d.source_id === ctx.current?.id && <p className="small"><Link to={`/hosts/${d.host_id}`}>Открыть полную карточку компьютера (данные KSC)</Link></p>}
        <h3 className="h3">Пользователи</h3>
        <dl className="kv">
          <div><dt>Вошли сейчас</dt><dd>{d.current.length ? d.current.map((u, i) => <span key={i} className="block"><UserChip u={u} /></span>) : "никого (по последнему опросу)"}</dd></div>
          <div><dt>Последний замеченный в сеансе</dt><dd>{d.last_user ? <><UserChip u={d.last_user} /> <span className="muted small">наблюдение {fmt(d.last_user.last_session_at)}</span></> : "не наблюдался: KSC не хранит последнего пользователя, наблюдения только за время работы KAV Checker"}</dd></div>
          <div><dt>За 7 суток ({d.week.length})</dt><dd>{d.week.length ? d.week.map((u, i) => <span key={i} className="block"><UserChip u={u} /></span>) : "—"}</dd></div>
          <div><dt>Входили ранее ({d.history.length})</dt><dd>{d.history.length ? <CompactList items={d.history} max={8} render={(u) => <UserChip u={u} />} /> : "—"}</dd></div>
        </dl>
        {d.hidden_service > 0 && <p className="muted small">Скрыто служебных и системных учётных записей: {d.hidden_service}.</p>}
        <p className="muted small">{d.limits}</p>
        <h3 className="h3">Программы и ОС без поддержки производителя</h3>
        {d.eol.length === 0 ? <p className="muted">Не найдено (или сопоставление с базой endoflife.date ещё не рассчитано).</p> : (
          <div className="table-scroll"><table className="table compact"><thead><tr><th>Критичность</th><th>Программа или ОС</th><th>Поддержка</th></tr></thead>
            <tbody>{d.eol.map((f) => <tr key={`${f.kind}${f.subject}${f.version}`}><td><EolSev f={f} /></td><td><strong>{f.title}</strong>{f.kind === "app" && <span className="sub mono small">{f.version}</span>}<span className="sub small">{f.eol_label}, ветка {f.eol_release}</span></td>
              <td><EolBadge s={f.status} short /><EolDates f={f} /></td></tr>)}</tbody></table></div>)}
        <p className="small"><Link to="/eol">Раздел EOL</Link> · {plural(d.eol.length, "проблема", "проблемы", "проблем")} поддержки: {d.eol.length}</p>
      </>}
    </Modal>
  );
}
