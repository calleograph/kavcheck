/** Инвентаризация со сканированием: список, создание (область — местоположение с вложенными и классы), сканирование по помещениям (камера, ручной сканер, этикетка помещения
 *  «LOC:<id>» переключает помещение), автономный режим (без связи отметки копятся на устройстве и отправляются позже), статистика по помещениям, расхождения и решения. */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ApiError } from "../../api";
import { Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { CheckAll, useRowSel } from "../../components/QuickReport";
import { useToast } from "../../components/Toast";
import { BackLink, Empty, Segmented, SkelRows, Tabs } from "../../components/ui";
import { fmt, fmtDate, num } from "../../util";
import { LocationPicker, PersonPicker, useInv } from "./InvBits";
import { Camera, hasDetector } from "./InvCamera";
import { useInvReport } from "./InvReport";
import { inv, type Count, type CountItem, type CountStats } from "./invApi";

const TONE: Record<string, string> = { found: "ok", moved: "warn", extra: "accent", unknown: "err", missing: "err", pending: "" };
const RES_RU: Record<string, string> = { found: "Найдено на месте", moved: "Найдено в другом месте", extra: "Не ожидалось здесь", unknown: "Код не найден в учёте", again: "Уже отмечено", queued: "Сохранено на устройстве — отправится при связи" };

export default function InvCounts() {
  const { can, meta } = useInv(); const nav = useNavigate();
  const [items, setItems] = useState<Count[] | null>(null); const [err, setErr] = useState(""); const [form, setForm] = useState(false);
  useEffect(() => { inv.counts().then((r) => setItems(r.items)).catch((e) => setErr((e as ApiError).message)); }, []);
  return (
    <div className="inv-page">
      <div className="inv-head"><h1>Инвентаризации</h1>{can("count") && <button className="btn primary" onClick={() => setForm(true)}><Icon name="plus" size={16} />Новая инвентаризация</button>}</div>
      {err && <p className="field-err">{err}</p>}
      {!items ? <div className="card"><SkelRows rows={4} cols={5} /></div> : !items.length ? <div className="card"><Empty icon="target" title="Инвентаризаций ещё не было"
        action={can("count") ? <button className="btn primary" onClick={() => setForm(true)}>Начать первую</button> : undefined}>
        Выберите здание или помещение — список ожидаемого оборудования зафиксируется. Затем отмечайте найденное камерой телефона или сканером; этикетка помещения переключает текущее помещение.</Empty></div> :
        <div className="table-scroll"><table className="table"><thead><tr><th>Номер</th><th>Область</th><th>Статус</th><th className="num">Ожидалось</th><th className="hide-sm">Начата</th><th className="hide-sm">Завершена</th></tr></thead>
          <tbody>{items.map((c) => <tr key={c.id} className="clickable" onClick={() => nav(`/inventory/counts/${c.id}`)}><td><Link to={`/inventory/counts/${c.id}`} className="mono">{c.no}</Link><span className="sub">{c.title}</span></td>
            <td className="small">{c.location}{c.cls && <span className="sub">{c.cls.split(",").map((x) => meta.cls[x]).join(", ")}</span>}</td><td><span className={`badge ${c.status === "active" ? "accent" : c.status === "closed" ? "ok" : ""}`}>{c.status_ru}</span></td>
            <td className="num">{num((c.stats as { expected?: number }).expected ?? null)}</td><td className="hide-sm nowrap">{fmtDate(c.started_at)}</td><td className="hide-sm nowrap">{fmtDate(c.closed_at)}</td></tr>)}</tbody></table></div>}
      {form && <CountForm onClose={() => setForm(false)} onCreated={(c) => nav(`/inventory/counts/${c.id}`)} />}
    </div>
  );
}

function CountForm({ onClose, onCreated }: { onClose: () => void; onCreated: (c: Count) => void }) {
  const { meta } = useInv();
  const [loc, setLoc] = useState<number | null>(null); const [cls, setCls] = useState<string[]>([]); const [title, setTitle] = useState(""); const [resp, setResp] = useState<number | null>(null); const [rname, setRname] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const go = async () => { setBusy(true); try { onCreated(await inv.addCount({ location_id: loc, cls: cls.join(","), title, resp_id: resp, start: true })); } catch (e) { setErr((e as ApiError).message); setBusy(false); } };
  return (
    <Modal title="Новая инвентаризация" lede="Ожидаемый список — действующее оборудование области, кроме отмеченного «не подлежит инвентаризации». Он фиксируется сразу." onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Отмена</button><div className="spacer" /><button className="btn primary" disabled={busy} onClick={() => void go()}>Начать</button></>}>
      <div className="form-stack">
        <LocationPicker label="Область: здание, этаж или помещение (с вложенными)" value={loc} onChange={setLoc} placeholder="всё оборудование" />
        <fieldset className="field"><legend>Классы (пусто — все)</legend><div className="row wrap tight">{Object.entries(meta.cls).map(([k, v]) => <label key={k} className="chip-check"><input type="checkbox" checked={cls.includes(k)} onChange={() => setCls(cls.includes(k) ? cls.filter((x) => x !== k) : [...cls, k])} />{v}</label>)}</div></fieldset>
        <label className="field">Название<input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="по области" maxLength={300} /></label>
        <PersonPicker label="Ответственный" value={resp} name={rname} onChange={(id, n) => { setResp(id); setRname(n); }} />
        {err && <p className="field-err">{err}</p>}
      </div>
    </Modal>
  );
}

// ------------------------------------------------------------------------------------------------ автономный режим: пакет ожидаемого и очередь отметок на устройстве
interface Pack { items: { asset_id: number; inv_no: string; serial: string; uid: string; name: string; exp_location_id: number | null }[]; locations: { id: number; path: string }[]; at: string }
interface Queued { code: string; location_id: number | null; user_id: number | null; at: string }
const store = {
  get<T>(k: string, d: T): T { try { const v = localStorage.getItem(k); return v ? (JSON.parse(v) as T) : d; } catch { return d; } },
  set(k: string, v: unknown) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* хранилище недоступно — работаем без него */ } },
};

type Tab = "scan" | "stats" | "diff" | "all";

export function CountPage() {
  const { id } = useParams(); const cid = Number(id);
  const { can, meta } = useInv();
  const [sp, setSp] = useSearchParams();
  const tab = ((["scan", "stats", "diff", "all"] as Tab[]).includes(sp.get("tab") as Tab) ? sp.get("tab") : "scan") as Tab;
  const [c, setC] = useState<Count | null>(null); const [err, setErr] = useState("");
  const [toast, show] = useToast();
  const rep = useInvReport();
  const load = useCallback(() => inv.count(cid).then((x) => { setC(x); setErr(""); }).catch((e) => setErr((e as ApiError).message)), [cid]);
  useEffect(() => { void load(); }, [load]);
  const [closing, setClosing] = useState(false);
  if (err) return <div className="card"><Empty icon="target" title="Инвентаризация недоступна">{err}</Empty></div>;
  if (!c) return <div className="card"><SkelRows rows={5} cols={3} /></div>;
  const st = c.stats as CountStats;
  const go = (t: Tab) => setSp((p) => { p.set("tab", t); return p; }, { replace: true });
  const done = st.expected ? Math.round((st.checked / st.expected) * 100) : 0;
  return (
    <div className="inv-page">
      <BackLink to="/inventory/counts" label="Инвентаризации" />
      <div className="inv-card-head">
        <div className="inv-card-title"><span className="inv-card-no mono">{c.no}</span><h1>{c.title}</h1>
          <div className="row tight wrap"><span className={`badge ${c.status === "active" ? "accent" : c.status === "closed" ? "ok" : ""}`}>{c.status_ru}</span><span className="muted small">{c.location} · начата {fmt(c.started_at)}{c.closed_at ? ` · завершена ${fmt(c.closed_at)}` : ""}</span></div></div>
        <div className="row wrap inv-card-actions">
          <button className="btn" onClick={() => rep.open(["count", "count_diff"], { count_id: c.id }, c.no)}><Icon name="download" size={16} />Отчёт</button>
          {c.status === "active" && can("count") && <button className="btn primary" onClick={() => setClosing(true)}>Завершить</button>}
        </div>
      </div>
      {st.by_state && <div className="meters">
        <div className="meter"><span className="l">Проверено</span><span className="v">{num(st.checked)}<small> / {num(st.expected)}</small></span><span className="t"><span className="inv-progress"><i style={{ width: `${done}%` }} /></span></span></div>
        <div className="meter"><button type="button" className="meter-link" onClick={() => go("diff")}><span className="l">Не найдено</span><span className={`v ${st.by_state.missing + (c.status === "closed" ? 0 : 0) ? "bad-text" : ""}`}>{num(c.status === "closed" ? st.by_state.missing : st.by_state.pending)}</span><span className="t">{c.status === "closed" ? "по итогам" : "ещё не отмечено"}</span></button></div>
        <div className="meter"><button type="button" className="meter-link" onClick={() => go("diff")}><span className="l">В другом месте · не ожидалось</span><span className={`v ${st.by_state.moved + st.by_state.extra ? "warn-text" : ""}`}>{num(st.by_state.moved)} · {num(st.by_state.extra + st.by_state.unknown)}</span><span className="t">включая коды без учётной карточки</span></button></div>
        <div className="meter"><span className="l">Другой пользователь</span><span className={`v ${st.user_diff ? "warn-text" : ""}`}>{num(st.user_diff)}</span><span className="t">отмечен фактический пользователь</span></div>
      </div>}
      <Tabs<Tab> label="Инвентаризация" value={tab} onChange={go} items={[...(c.status === "active" ? [{ id: "scan" as Tab, label: "Сканирование" }] : []), { id: "stats", label: "По помещениям" }, { id: "diff", label: "Расхождения" }, { id: "all", label: "Все строки" }]} />
      {tab === "scan" && c.status === "active" && <ScanTab c={c} onChange={load} show={show} />}
      {tab === "stats" && <StatsTab st={st} onPick={(lid) => { setSp((p) => { p.set("tab", "scan"); if (lid) p.set("loc", String(lid)); else p.delete("loc"); return p; }); }} active={c.status === "active"} />}
      {tab === "diff" && <ItemsTab c={c} diff onChange={load} show={show} />}
      {tab === "all" && <ItemsTab c={c} onChange={load} show={show} />}
      {closing && <Modal title={`Завершить ${c.no}?`} lede="Неотмеченное станет «Не найдено». Учётные данные не изменятся: решения по расхождениям принимаются после завершения во вкладке «Расхождения»." onClose={() => setClosing(false)}
        footer={<><button className="btn" onClick={() => setClosing(false)}>Отмена</button><div className="spacer" /><button className="btn primary" onClick={() => void inv.closeCount(c.id).then(() => { setClosing(false); go("diff"); void load(); show("Инвентаризация завершена"); }).catch((e) => show((e as ApiError).message, "error"))}>Завершить</button></>}>
        <p>Ещё не отмечено: <b>{num(st.by_state?.pending ?? 0)}</b>. {meta.st.lost ? "«Утрачено» можно назначить решением по не найденному." : ""}</p></Modal>}
      {rep.node}{toast}
    </div>
  );
}

function ScanTab({ c, onChange, show }: { c: Count; onChange: () => void; show: (t: string, tone?: "ok" | "error") => void }) {
  const [sp, setSp] = useSearchParams();
  const key = `kc:inv-count:${c.id}`;
  const [pack, setPack] = useState<Pack | null>(() => store.get<Pack | null>(`${key}:pack`, null));
  const [queue, setQueue] = useState<Queued[]>(() => store.get<Queued[]>(`${key}:queue`, []));
  const firstLeft = ((c.stats as CountStats).locations ?? []).find((l) => l.left > 0)?.location_id ?? null;
  const [loc, setLoc] = useState<number | null>(sp.get("loc") ? Number(sp.get("loc")) : firstLeft ?? c.location_id);
  const [userId, setUserId] = useState<number | null>(null); const [uname, setUname] = useState("");
  const [code, setCode] = useState(""); const [cam, setCam] = useState(false); const [camErr, setCamErr] = useState("");
  const [last, setLast] = useState<{ result: string; item?: CountItem; code: string }[]>([]);
  const [here, setHere] = useState<CountItem[] | null>(null);
  const input = useRef<HTMLInputElement>(null); const recent = useRef<Record<string, number>>({});
  const loadPack = useCallback(() => inv.countOffline(c.id).then((p) => { setPack(p as unknown as Pack); store.set(`${key}:pack`, p); }).catch(() => undefined), [c.id, key]);
  useEffect(() => { void loadPack(); }, [loadPack]);
  const loadHere = useCallback(() => { if (loc === null) { setHere([]); return; } inv.countItems(c.id, { location: loc, limit: 2000 }).then((r) => setHere(r.items)).catch(() => undefined); }, [c.id, loc]);
  useEffect(() => { loadHere(); }, [loadHere]);
  useEffect(() => { setSp((p) => { if (loc) p.set("loc", String(loc)); else p.delete("loc"); return p; }, { replace: true }); }, [loc]); // eslint-disable-line react-hooks/exhaustive-deps
  const saveQueue = (q: Queued[]) => { setQueue(q); store.set(`${key}:queue`, q); };
  const flush = useCallback(async () => {
    const q = store.get<Queued[]>(`${key}:queue`, []); if (!q.length) return;
    try { const r = await inv.countSync(c.id, q); saveQueue([]); show(`Отправлено отметок: ${r.results.length}`); onChange(); loadHere(); } catch { /* связи всё ещё нет */ }
  }, [c.id, key, onChange, loadHere, show]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { const h = () => void flush(); window.addEventListener("online", h); void flush(); return () => window.removeEventListener("online", h); }, [flush]);
  const locName = (id: number | null) => pack?.locations.find((l) => l.id === id)?.path ?? (id === null ? "не выбрано" : `#${id}`);
  const handle = async (raw: string) => {
    const v = raw.trim(); if (!v) return;
    const now = Date.now(); if (recent.current[v] && now - recent.current[v] < 2500) return; recent.current[v] = now;   // камера видит код несколько раз подряд
    const m = /^LOC:(\d+)$/i.exec(v);
    if (m) { setLoc(Number(m[1])); show(`Помещение: ${locName(Number(m[1]))}`); return; }
    try {
      const r = await inv.countScan(c.id, { code: v, location_id: loc, user_id: userId });
      setLast((x) => [{ result: r.result, item: r.item, code: v }, ...x].slice(0, 12)); if (navigator.vibrate) navigator.vibrate(r.result === "found" ? 40 : [40, 60, 40]);
      onChange(); loadHere();
    } catch (e) {
      if ((e as ApiError).status === 0) {                       // нет связи: отметка — в очередь на устройстве, распознавание по пакету
        const a = pack?.items.find((x) => [x.inv_no, x.serial].some((y) => y && y.toLowerCase() === v.toLowerCase()) || (x.uid && v.includes(x.uid)));
        saveQueue([...store.get<Queued[]>(`${key}:queue`, []), { code: v, location_id: loc, user_id: userId, at: new Date().toISOString() }]);
        setLast((x) => [{ result: "queued", code: a ? `${a.inv_no} · ${a.name}` : v }, ...x].slice(0, 12));
      } else show((e as ApiError).message, "error");
    }
  };
  const expectedHere = (here ?? []).filter((i) => i.expected && i.exp_location_id === loc);
  const left = expectedHere.filter((i) => i.state === "pending");
  return (
    <div className="stack">
      <div className="card inv-scanbar">
        <div className="inv-grid">
          <LocationPicker label="Текущее помещение (или отсканируйте его этикетку)" value={loc} onChange={setLoc} />
          <PersonPicker label="Фактический пользователь (необязательно)" value={userId} name={uname} onChange={(id, n) => { setUserId(id); setUname(n); }} />
        </div>
        <form className="row wrap" onSubmit={(e) => { e.preventDefault(); void handle(code); setCode(""); input.current?.focus(); }}>
          <div className="input-icon grow"><Icon name="search" size={16} /><input ref={input} autoFocus value={code} onChange={(e) => setCode(e.target.value)} placeholder="Отсканируйте этикетку или введите номер и нажмите Enter" aria-label="Код или номер" /></div>
          <button className="btn primary" type="submit">Отметить</button>
          {hasDetector() && <button type="button" className={`btn ${cam ? "" : "ghost"}`} onClick={() => setCam(!cam)}><Icon name={cam ? "stop" : "eye"} size={16} />{cam ? "Выключить камеру" : "Камера"}</button>}
        </form>
        {camErr && <p className="field-err">{camErr}</p>}
        <Camera on={cam} onCode={(v) => void handle(v)} onError={(m) => { setCamErr(m); setCam(false); }} />
        <div className="row wrap small muted">
          {queue.length > 0 ? <><span className="badge warn">не отправлено: {queue.length}</span><button type="button" className="btn mini" onClick={() => void flush()}>Отправить сейчас</button></>
            : <span>Без связи отметки сохраняются на этом устройстве и отправляются при восстановлении сети{pack ? ` · список для работы без связи загружен ${fmt(pack.at)}` : ""}.</span>}
        </div>
      </div>
      {last.length > 0 && <ul className="inv-scanlog" aria-live="polite">{last.map((l, i) => <li key={i} className={`r-${l.result}`}>
        <span className={`badge ${TONE[l.result] ?? ""}`}>{RES_RU[l.result] ?? l.result}</span>
        {l.item?.asset_id ? <Link to={`/inventory/assets/${l.item.asset_id}`} className="mono">{l.item.inv_no}</Link> : <span className="mono">{l.code}</span>}
        <span>{l.item?.name}</span>{l.result === "moved" && l.item && <span className="muted small">по учёту: {l.item.exp_location}</span>}</li>)}</ul>}
      <div className="card flush"><div className="card-head"><h2>Ожидается в «{locName(loc)}»</h2><div className="spacer" /><span className={`badge ${expectedHere.length && !left.length ? "ok" : ""}`}>{expectedHere.length - left.length} из {expectedHere.length}</span></div>
        {loc === null ? <p className="muted small pad">Выберите помещение или отсканируйте его этикетку.</p> : !here ? <SkelRows rows={3} cols={3} /> : !expectedHere.length ? <p className="muted small pad">По учёту здесь ничего нет.</p> :
          <div className="table-scroll"><table className="table compact"><thead><tr><th>Инв. номер</th><th>Наименование</th><th className="hide-sm">Серийный номер</th><th>Отметка</th></tr></thead>
            <tbody>{[...left, ...expectedHere.filter((i) => i.state !== "pending")].map((i) => <tr key={i.id} className={i.state === "found" ? "row-ok" : ""}><td className="mono">{i.inv_no}</td><td>{i.name}</td><td className="hide-sm mono small">{i.serial}</td>
              <td>{i.state === "pending" ? <span className="muted small">ожидается</span> : <span className={`badge ${TONE[i.state]}`}>{i.state_ru}</span>}</td></tr>)}</tbody></table></div>}
      </div>
    </div>
  );
}

function StatsTab({ st, onPick, active }: { st: CountStats; onPick: (lid: number | null) => void; active: boolean }) {
  if (!st.locations?.length) return <div className="card"><Empty icon="sitemap" title="Нет данных">Ожидаемый список пуст.</Empty></div>;
  return (
    <div className="table-scroll"><table className="table"><thead><tr><th>Помещение</th><th className="num">Ожидалось</th><th className="num">На месте</th><th className="num">В другом месте</th><th className="num">Осталось</th><th /></tr></thead>
      <tbody>{st.locations.map((l) => <tr key={String(l.location_id)} className={l.done ? "row-ok" : ""}><td>{l.location}</td><td className="num">{l.expected}</td><td className="num">{l.found}</td><td className="num">{l.moved_out}</td>
        <td className="num">{l.left ? <b>{l.left}</b> : <span className="badge ok">готово</span>}</td><td>{active && <button className="btn mini" onClick={() => onPick(l.location_id)}>Сканировать здесь</button>}</td></tr>)}</tbody></table></div>
  );
}

function ItemsTab({ c, diff, onChange, show }: { c: Count; diff?: boolean; onChange: () => void; show: (t: string, tone?: "ok" | "error") => void }) {
  const { can } = useInv();
  const [state, setState] = useState(""); const [rows, setRows] = useState<CountItem[] | null>(null); const [total, setTotal] = useState(0);
  const sel = useRowSel<number>();
  const load = useCallback(() => inv.countItems(c.id, { diff: diff || undefined, state, limit: 2000 }).then((r) => { setRows(r.items); setTotal(r.total); }).catch((e) => show((e as ApiError).message, "error")), [c.id, diff, state, show]);
  useEffect(() => { void load(); }, [load]);
  const decide = async (d: string) => { try { const r = await inv.countDecide(c.id, sel.ids, d); show(r.changed ? `Изменено карточек: ${r.changed}` : "Решение сохранено"); sel.clear(); void load(); onChange(); } catch (e) { show((e as ApiError).message, "error"); } };
  const unscan = async (it: CountItem) => { try { await inv.countUnscan(c.id, it.id); void load(); onChange(); } catch (e) { show((e as ApiError).message, "error"); } };
  const opts = useMemo<[string, string][]>(() => diff ? [["", "Все расхождения"], ["moved", "В другом месте"], ["extra", "Не ожидалось"], ["unknown", "Нет в учёте"], ["missing,pending", "Не найдено"]]
    : [["", "Все"], ["found", "На месте"], ["moved", "В другом месте"], ["extra", "Не ожидалось"], ["pending", "Ожидается"], ["missing", "Не найдено"]], [diff]);
  return (
    <div className="stack">
      <div className="row wrap"><Segmented label="Отбор" value={state} onChange={setState} options={opts} /><span className="muted small">{num(total)} строк</span></div>
      {diff && <p className="muted small">Обнаружение само по себе учёт не меняет. «Принять фактическое» записывает в карточку место, где единица найдена (и фактического пользователя, если он отмечен); «Утрачено» — для не найденного (право списания). Каждое изменение попадает в историю карточки с номером инвентаризации.</p>}
      {!rows ? <div className="card"><SkelRows rows={4} cols={5} /></div> : !rows.length ? <div className="card"><Empty icon="check" title={diff ? "Расхождений нет" : "Строк нет"} /></div> :
        <div className="table-scroll"><table className="table compact"><thead><tr>{diff && can("count") && <CheckAll all={sel.allOf(rows.map((r) => r.id))} some={sel.someOf(rows.map((r) => r.id))} onToggle={() => sel.toggleMany(rows.map((r) => r.id))} />}
          <th>Результат</th><th>Инв. номер</th><th>Наименование</th><th className="hide-sm">По учёту</th><th className="hide-sm">Найдено в</th><th className="hide-md">Пользователь</th><th>Решение</th>{!diff && c.status === "active" && <th />}</tr></thead>
          <tbody>{rows.map((r) => <tr key={r.id} className={sel.has(r.id) ? "sel" : ""}>
            {diff && can("count") && <td className="check"><input type="checkbox" aria-label={`Выбрать ${r.inv_no || r.code}`} checked={sel.has(r.id)} onChange={() => sel.toggle(r.id)} /></td>}
            <td><span className={`badge ${TONE[r.state] ?? ""}`}>{r.state_ru}</span>{r.user_diff && <span className="badge warn">другой пользователь</span>}</td>
            <td>{r.asset_id ? <Link to={`/inventory/assets/${r.asset_id}`} className="mono">{r.inv_no}</Link> : <span className="mono">{r.code}</span>}</td>
            <td>{r.name}<span className="sub mono">{r.serial}</span></td><td className="hide-sm small">{r.exp_location}</td><td className="hide-sm small">{r.found_location}{r.found_at && <span className="sub">{fmt(r.found_at)} · {r.found_by}</span>}</td>
            <td className="hide-md small">{r.user}{r.user_diff && <span className="sub warn-text">факт: {r.found_user}</span>}</td><td className="small">{r.decision_ru || <span className="muted">—</span>}</td>
            {!diff && c.status === "active" && <td>{r.found_at && can("count") && <button className="btn mini ghost" onClick={() => void unscan(r)}>Отменить отметку</button>}</td>}</tr>)}</tbody></table></div>}
      {diff && sel.count > 0 && <div className="row wrap inv-decide">
        <span><b>{sel.count}</b> выбрано</span>
        <button className="btn mini primary" onClick={() => void decide("apply")}>Принять фактическое</button>
        <button className="btn mini" onClick={() => void decide("keep")}>Оставить учётное</button>
        {can("writeoff") && <button className="btn mini" onClick={() => void decide("lost")}>Утрачено</button>}
        <button className="btn mini ghost" onClick={() => void decide("ignore")}>Без изменений</button></div>}
    </div>
  );
}
