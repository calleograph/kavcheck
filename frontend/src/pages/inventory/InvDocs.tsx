/** Документы инвентаризации: журнал, оформление (выдача, возврат, перемещение, приём-передача, передача МЦ, приём неисправного, ремонт, списание, работа),
 *  этапы с применением изменений к карточкам на «своём» этапе и печатные формы (HTML, PDF, DOCX). */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import type { ApiError } from "../../api";
import type { Ctx } from "../../App";
import { Modal } from "../../components/Dialogs";
import { FilterBar } from "../../components/FilterBar";
import { Icon } from "../../components/Icons";
import { ListFoot, VirtualRows, useInfinite, type Chunk } from "../../components/Infinite";
import { useToast } from "../../components/Toast";
import { BackLink, Empty, SkelRows } from "../../components/ui";
import { fmt, fmtDate } from "../../util";
import { AssetSearch, Kv, LocationPicker, PersonPicker, RefSelect, StBadge, shortLabel, useInv } from "./InvBits";
import { useInvReport } from "./InvReport";
import { inv, type Asset, type Doc, type DocCard } from "./invApi";

const TONE: Record<string, string> = { draft: "", prepared: "accent", sent: "warn", accepted: "accent", done: "ok", cancelled: "" };
/** Что произойдёт с карточками при переходе — пишется на кнопке и в подтверждении. */
const EFFECT: Record<string, Record<string, string>> = {
  move: { prepared: "Документ готов к отправке. Карточки не меняются.", sent: "Оборудование будет отмечено «в пути»; местоположение пока прежнее.", accepted: "Новое местоположение и ответственные будут записаны в карточки.", done: "Документ закрывается.", cancelled: "Отметка «в пути» будет снята, карточки не меняются." },
  receipt: { sent: "Поступление отмечено как заказанное. Карточки ещё не создаются; строки можно поправить.", done: "На складе будет создана карточка на каждую единицу (статус «На складе», поставщик, документ приобретения, гарантия).", cancelled: "Поступление отменяется." },
  repair: { sent: "Статус оборудования станет «В ремонте», прежний статус запоминается.", done: "Оборудование возвращено: прежний статус будет восстановлен.", cancelled: "Документ отменяется без изменений карточек." },
  default: { prepared: "Документ подготовлен (можно распечатать и подписать). Карточки не меняются.", done: "Изменения будут записаны в карточки оборудования и их историю.", draft: "Документ вернётся в черновик.", cancelled: "Документ отменяется без изменений карточек.", sent: "Работа в процессе." },
};
const effect = (kind: string, to: string) => EFFECT[kind]?.[to] ?? EFFECT.default[to] ?? "";
const NEXT_LABEL: Record<string, string> = { prepared: "Подготовить", sent: "Отправить", accepted: "Принять", done: "Провести", cancelled: "Отменить", draft: "Вернуть в черновик" };
const DOC_HINT: Record<string, string> = {
  issue: "Оборудование закрепляется за сотрудником (пользователь), статус — «В эксплуатации», местоположение — если указано.",
  return: "Снимается пользователь (и выбранные роли), статус — «На складе», местоположение — склад, если указан.",
  move: "Перемещение в три шага: подготовка → отправка (оборудование «в пути») → приём (новое место и ответственные).",
  accept: "Приём-передача: назначается ответственный (или выбранная роль) и местоположение.", handover: "Передача материальных ценностей: назначается новое МОЛ.",
  defect: "Приём неисправного оборудования: фиксируется состояние, местоположение (например, склад ИТ).", repair: "Ремонт: при отправке — статус «В ремонте», при возврате — прежний статус.",
  writeoff: "Списание: статус «Списано», пользователь снимается. Карточки не удаляются.",
  decom: "Вывод из эксплуатации: статус «Выведено из эксплуатации», связь ВМ с хостом снимается, проверочный список — в акте. Карточки и история сохраняются.",
  receipt: "Поступление: заказ (строки — тип или модель, количество, цена, гарантия, серийные номера) → «Заказано» → «Принято»: на складе создаётся карточка на каждую единицу.", work: "Работа с оборудованием: исполнитель, срок, результат; при выполнении — запись в историю каждой единицы.",
};

export default function InvDocs({ ctx }: { ctx: Ctx }) {
  void ctx;
  const { meta, can } = useInv();
  const [sp, setSp] = useSearchParams(); const nav = useNavigate();
  const kind = sp.get("kind") ?? "", status = sp.get("status") ?? "", openOnly = sp.get("open_only") === "1";
  const [q, setQ] = useState(sp.get("q") ?? "");
  const [aq, setAq] = useState(q);
  useEffect(() => { const t = window.setTimeout(() => setAq(q), 350); return () => window.clearTimeout(t); }, [q]);
  const set = (k: string, v: string) => setSp((p) => { if (v) p.set(k, v); else p.delete(k); return p; }, { replace: true });
  const list = useInfinite<Doc>("inv-docs", [kind, status, openOnly, aq], (offset, limit) => inv.docs({ kind, status, open_only: openOnly || undefined, q: aq, offset, limit }) as unknown as Promise<Chunk<Doc>>);
  const rep = useInvReport();
  const kinds = Object.keys(meta.doc_short).filter((k) => k !== "repair" || can("repair")).filter((k) => k !== "writeoff" || can("writeoff"));
  return (
    <div className="inv-page">
      <div className="inv-head"><h1>Документы</h1>
        {can("docs") && <div className="row wrap inv-doc-new" role="group" aria-label="Сформировать документ"><span className="muted small">Сформировать:</span>{["issue", "return", "move"].map((k) => <button key={k} className={`btn ${k === "issue" ? "primary" : ""}`} onClick={() => nav(`/inventory/docs/new?kind=${k}`)}><Icon name="file" size={16} />{DOC_NEW[k]}</button>)}
          <select className="btn-select" value="" aria-label="Другой документ" onChange={(e) => e.target.value && nav(`/inventory/docs/new?kind=${e.target.value}`)}><option value="">Другой документ…</option>{kinds.filter((k) => !["issue", "return", "move"].includes(k)).map((k) => <option key={k} value={k}>{meta.doc_short[k]}</option>)}</select></div>}
      </div>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Номер, основание, инвентарный номер оборудования", label: "Поиск документов" }}
        primary={<>
          <label className="field inline"><span className="sr-only">Вид</span><select value={kind} onChange={(e) => set("kind", e.target.value)}><option value="">Все виды</option>{Object.entries(meta.doc_short).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="field inline"><span className="sr-only">Этап</span><select value={status} onChange={(e) => set("status", e.target.value)}><option value="">Любой этап</option>{Object.entries(meta.doc_status).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="chip-check"><input type="checkbox" checked={openOnly} onChange={(e) => set("open_only", e.target.checked ? "1" : "")} />только незавершённые</label>
        </>}
        chips={[...(kind ? [{ id: "k", label: meta.doc_short[kind] ?? kind, onRemove: () => set("kind", "") }] : []), ...(status ? [{ id: "s", label: meta.doc_status[status] ?? status, onRemove: () => set("status", "") }] : []), ...(openOnly ? [{ id: "o", label: "Незавершённые", onRemove: () => set("open_only", "") }] : [])]}
        onReset={() => { setQ(""); setSp(new URLSearchParams(), { replace: true }); }} count={{ n: list.initial ? null : list.total, noun: ["документ", "документа", "документов"] }} onRefresh={() => list.reload()} refreshing={list.refreshing}
        report={{ onClick: () => rep.open(["docs"], { doc_kind: kind }, "Журнал документов"), title: "Журнал документов" }} />
      <div className="table-scroll">
        {list.initial ? <SkelRows cols={7} /> : <table className="table virt"><thead><tr><th>Номер</th><th>Вид</th><th>Дата</th><th>Этап</th><th className="hide-sm">Стороны</th><th className="hide-sm">Единиц</th><th className="hide-sm">Файл</th></tr></thead>
          <tbody><VirtualRows list={list} colSpan={7} estimate={46} row={(d) => <tr>
            <td className="nowrap"><Link to={`/inventory/docs/${d.id}`} className="mono">{d.no}</Link></td><td>{d.kind_ru}</td><td className="nowrap">{fmtDate(d.date)}</td><td><span className={`badge ${TONE[d.status]}`}>{d.status_ru}</span></td>
            <td className="hide-sm small" title={[d.from_person || d.from_location, d.to_person || d.to_location].filter(Boolean).join(" → ")}>{[d.from_person || tail(d.from_location), d.to_person || tail(d.to_location)].filter(Boolean).join(" → ") || "—"}</td><td className="hide-sm num">{d.items_n}</td><td className="hide-sm nowrap"><DocFiles id={d.id} compact /></td></tr>} />
            {!list.items.length && !list.loading && <tr><td colSpan={7}><Empty icon="file" title="Документов нет">Выдача, возврат и перемещение оформляются здесь или из карточки оборудования.</Empty></td></tr>}</tbody></table>}
      </div>
      <ListFoot list={list} />
      {rep.node}
    </div>
  );
}

// ------------------------------------------------------------------------------------------------ редактор
interface Draft { kind: string; date: string; from_location_id: number | null; to_location_id: number | null; from_person_id: number | null; to_person_id: number | null; resp_id: number | null; basis: string; comment: string;
  data: Record<string, unknown>; items: { asset: Asset; condition: string; note: string }[]; names: Record<string, string> }

function DocEditor({ init, onSaved, onCancel, docId }: { init: Draft; onSaved: (d: DocCard) => void; onCancel: () => void; docId?: number }) {
  const { meta } = useInv();
  const [d, setD] = useState<Draft>(init); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((x) => ({ ...x, [k]: v }));
  const setData = (k: string, v: unknown) => setD((x) => ({ ...x, data: { ...x.data, [k]: v } }));
  const person = (k: "from_person_id" | "to_person_id" | "resp_id", lb: string) => <PersonPicker label={lb} value={d[k]} name={d.names[k]} onChange={(id, nm) => setD((x) => ({ ...x, [k]: id, names: { ...x.names, [k]: nm } }))} />;
  const k = d.kind;
  const add = (a: Asset) => setD((x) => (x.items.some((i) => i.asset.id === a.id) ? x : { ...x, items: [...x.items, { asset: a, condition: "", note: "" }] }));
  const save = async () => {
    setBusy(true); setErr("");
    const body = { kind: k, date: d.date || undefined, from_location_id: d.from_location_id, to_location_id: d.to_location_id, from_person_id: d.from_person_id, to_person_id: d.to_person_id, resp_id: d.resp_id,
      basis: d.basis, comment: d.comment, data: d.data, items: d.items.map((i) => ({ asset_id: i.asset.id, condition: i.condition, note: i.note })) };
    try { onSaved(docId ? await inv.editDoc(docId, body) : await inv.addDoc(body)); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); }
  };
  const roleSel = (lb: string, def: string) => <label className="field">{lb}<select value={String(d.data.role ?? def)} onChange={(e) => setData("role", e.target.value)}><option value="">не назначать</option>{Object.entries(meta.roles).map(([r, v]) => <option key={r} value={r}>{v}</option>)}</select></label>;
  return (
    <form className="inv-form" onSubmit={(e) => { e.preventDefault(); void save(); }}>
      <p className="muted small">{DOC_HINT[k]}</p>
      <fieldset className="inv-fs"><legend>Реквизиты</legend><div className="inv-grid">
        <label className="field">Дата документа<input type="date" value={d.date} onChange={(e) => set("date", e.target.value)} /></label>
        {["return", "handover", "accept", "defect"].includes(k) && person("from_person_id", k === "return" ? "Сотрудник (сдаёт)" : "Передающая сторона")}
        {["issue", "handover", "accept", "move"].includes(k) && person("to_person_id", k === "issue" ? "Сотрудник (получает)" : k === "move" ? "Получатель" : "Принимающая сторона")}
        {["move"].includes(k) && <LocationPicker label="Откуда" value={d.from_location_id} onChange={(v) => set("from_location_id", v)} placeholder="по текущему месту" />}
        {["issue", "return", "move", "accept", "handover", "defect", "receipt"].includes(k) && <LocationPicker label={k === "move" ? "Куда" : ["return", "defect", "receipt"].includes(k) ? "Куда принять (склад)" : "Местоположение"} value={d.to_location_id} onChange={(v) => set("to_location_id", v)} placeholder="не менять" />}
        {k === "move" && roleSel("Получатель становится", "")}
        {k === "accept" && roleSel("Принимающая сторона становится", "resp")}
        {k === "issue" && <fieldset className="field"><legend>Также назначить сотрудника</legend><div className="row wrap tight">{(["owner", "resp"] as const).map((r) => {
          const cur = (d.data.also_roles as string[] | undefined) ?? [];
          return <label key={r} className="chip-check"><input type="checkbox" checked={cur.includes(r)} onChange={() => setData("also_roles", cur.includes(r) ? cur.filter((x) => x !== r) : [...cur, r])} />{meta.roles[r]}</label>;
        })}</div></fieldset>}
        {k === "return" && <fieldset className="field"><legend>Также снять</legend><div className="row wrap tight">{(["owner", "resp"] as const).map((r) => {
          const cur = (d.data.clear_roles as string[] | undefined) ?? [];
          return <label key={r} className="chip-check"><input type="checkbox" checked={cur.includes(r)} onChange={() => setData("clear_roles", cur.includes(r) ? cur.filter((x) => x !== r) : [...cur, r])} />{meta.roles[r]}</label>;
        })}</div></fieldset>}
        {person("resp_id", "Ответственный за операцию")}
        {["issue", "return", "accept", "handover", "defect"].includes(k) && <RefSelect kind="status" label="Статус после проведения" value={(d.data.status_id as number) ?? null} onChange={(v) => setData("status_id", v)} empty="по виду документа" />}
        <label className="field wide">Основание<input value={d.basis} onChange={(e) => set("basis", e.target.value)} maxLength={500} placeholder="приказ, заявка, служебная записка" /></label>
      </div></fieldset>
      {k === "repair" && <fieldset className="inv-fs"><legend>Ремонт</legend><div className="inv-grid">
        <label className="field wide">Неисправность<input value={String(d.data.fault ?? "")} onChange={(e) => setData("fault", e.target.value)} /></label>
        <label className="field">Дата обнаружения<input type="date" value={String(d.data.found_at ?? "")} onChange={(e) => setData("found_at", e.target.value)} /></label>
        <label className="field">Исполнитель / сервисная организация<input value={String(d.data.vendor ?? "")} onChange={(e) => setData("vendor", e.target.value)} list="inv-suppliers" /></label>
        <datalist id="inv-suppliers">{meta.refs.filter((r) => r.kind === "supplier").map((r) => <option key={r.id} value={r.name} />)}</datalist>
        <label className="check-row"><input type="checkbox" checked={!!d.data.warranty} onChange={(e) => setData("warranty", e.target.checked)} />Гарантийный ремонт</label>
      </div></fieldset>}
      {k === "work" && <fieldset className="inv-fs"><legend>Работа</legend><div className="inv-grid">
        <label className="field">Вид работ<select value={String(d.data.work_kind ?? "")} onChange={(e) => setData("work_kind", e.target.value)}><option value="">—</option>{Object.entries(meta.work_kinds).map(([w, v]) => <option key={w} value={w}>{v}</option>)}</select></label>
        <label className="field">Исполнитель<input value={String(d.data.executor ?? "")} onChange={(e) => setData("executor", e.target.value)} /></label>
        <label className="field">Срок<input type="date" value={String(d.data.due ?? "")} onChange={(e) => setData("due", e.target.value)} /></label>
        <label className="field wide">Описание<textarea rows={2} value={String(d.data.description ?? "")} onChange={(e) => setData("description", e.target.value)} /></label>
      </div></fieldset>}
      {k === "receipt" && <ReceiptLines d={d} setData={setData} />}
      {k === "decom" && <fieldset className="inv-fs"><legend>Проверочный список вывода</legend><div className="row wrap tight">{([["monitoring", "Снят с мониторинга"], ["backup", "Резервное копирование прекращено или не требуется"], ["ips", "IP-адреса освобождены"], ["links", "Связи с хостами и кластерами сняты"]] as [string, string][]).map(([key, lb]) => {
        const ck = (d.data.checklist as Record<string, boolean> | undefined) ?? {};
        return <label key={key} className="chip-check"><input type="checkbox" checked={!!ck[key]} onChange={(e) => setData("checklist", { ...ck, [key]: e.target.checked })} />{lb}</label>;
      })}</div><p className="muted small">Действия во внешних системах выполняет администратор; отметки попадают в акт и историю. Если узел остаётся в мониторинге или резервном копировании, сверка покажет это расхождением.</p></fieldset>}
      {k !== "receipt" && <fieldset className="inv-fs"><legend>Оборудование ({d.items.length})</legend>
        <AssetSearch onPick={add} exclude={d.items.map((i) => i.asset.id)} placeholder="Номер, серийный номер, название — или отсканируйте этикетку и нажмите Enter" />
        {d.items.length > 0 && <div className="table-scroll"><table className="table compact inv-doc-items"><thead><tr><th>Инв. номер</th><th>Наименование</th><th className="hide-sm">Сейчас</th><th>Состояние</th><th className="hide-sm">Примечание</th><th /></tr></thead><tbody>
          {d.items.map((i, n) => <tr key={i.asset.id}><td className="mono nowrap">{i.asset.inv_no}</td><td>{shortLabel(i.asset)}<span className="sub mono">{i.asset.serial}</span></td>
            <td className="hide-sm small"><StBadge st={i.asset.st_cls} label={i.asset.status} />{i.asset.user && <span className="sub">{i.asset.user}</span>}<span className="sub">{i.asset.location}</span></td>
            <td><input className="mini" value={i.condition} aria-label={`Состояние ${i.asset.inv_no}`} onChange={(e) => setD((x) => ({ ...x, items: x.items.map((y, m) => (m === n ? { ...y, condition: e.target.value } : y)) }))} placeholder="исправно" /></td>
            <td className="hide-sm"><input className="mini" value={i.note} aria-label={`Примечание ${i.asset.inv_no}`} onChange={(e) => setD((x) => ({ ...x, items: x.items.map((y, m) => (m === n ? { ...y, note: e.target.value } : y)) }))} /></td>
            <td><button type="button" className="btn ghost icon mini" aria-label={`Убрать ${i.asset.inv_no}`} onClick={() => setD((x) => ({ ...x, items: x.items.filter((_, m) => m !== n) }))}><Icon name="close" size={14} /></button></td></tr>)}</tbody></table></div>}
      </fieldset>}
      <label className="field wide">Примечание к документу<textarea rows={2} value={d.comment} onChange={(e) => set("comment", e.target.value)} /></label>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="inv-form-foot"><button type="button" className="btn" onClick={onCancel}>Отмена</button><div className="spacer" /><button type="submit" className="btn primary" disabled={busy || (k === "receipt" ? !((d.data.lines as unknown[] | undefined) ?? []).length : !d.items.length)}>{docId ? "Сохранить" : "Создать черновик"}</button></div>
    </form>
  );
}

/** последний уровень пути местоположения: полный путь — в подсказке */
const tail = (path: string) => path.split(" / ").slice(-2).join(" / ");

const DOC_NEW: Record<string, string> = { issue: "Акт выдачи", return: "Акт возврата", move: "Накладная на перемещение" };

/** Сформировать файл документа: Word, Excel, PDF, HTML (тот же состав, что у печатной формы). compact — короткие ссылки для строки таблицы. */
export function DocFiles({ id, compact, noPrint }: { id: number; compact?: boolean; noPrint?: boolean }) {
  const f: ["docx" | "xlsx" | "pdf" | "html", string, string][] = [["docx", "Word", "DOCX"], ["xlsx", "Excel", "XLSX"], ["pdf", "PDF", "PDF"], ["html", "HTML", "HTML"]];
  if (compact) return <span className="row tight">{f.slice(0, 3).map(([k, , short]) => <a key={k} className="btn ghost mini" href={inv.printUrl(id, k)} {...(k === "pdf" ? { target: "_blank", rel: "noopener" } : {})} title={`Сформировать ${short}`}>{short}</a>)}</span>;
  return (
    <div className="row wrap tight inv-gen-btns">
      {f.map(([k, lb, short]) => <a key={k} className={`btn ${k === "docx" ? "primary" : ""}`} title={`Сформировать файл ${short}`} href={inv.printUrl(id, k)} {...(k === "pdf" ? { target: "_blank", rel: "noopener" } : {})}><Icon name="download" size={16} />{lb}</a>)}
      {!noPrint && <Link className="btn ghost" to={`/inventory/docs/${id}/print`}><Icon name="file" size={16} />Открыть для печати</Link>}
    </div>
  );
}

export function DocNew() {
  const [sp] = useSearchParams(); const nav = useNavigate(); const { meta, can } = useInv();
  const kind = sp.get("kind") ?? "issue";
  const [items, setItems] = useState<Asset[] | null>(null);
  const ids = sp.get("ids") ?? "";
  useEffect(() => { if (!ids) { setItems([]); return; } inv.assets({ ids, limit: 500 }).then((r) => setItems(r.items)).catch(() => setItems([])); }, [ids]);
  const init = useMemo<Draft | null>(() => items && ({ kind, date: new Date().toISOString().slice(0, 10), from_location_id: null, to_location_id: null, from_person_id: sp.get("from") ? Number(sp.get("from")) : null,
    to_person_id: null, resp_id: null, basis: "", comment: "", data: kind === "move" ? { role: "" } : {}, items: items.map((a) => ({ asset: a, condition: "", note: "" })),
    names: { from_person_id: sp.get("from") ? items[0]?.user ?? "" : "" } }), [items, kind, sp]);
  if (!meta.doc_kinds[kind]) return <Empty icon="file" title="Неизвестный вид документа" />;
  if (!can(kind === "repair" ? "repair" : kind === "writeoff" ? "writeoff" : kind === "receipt" ? "create" : "docs")) return <div className="card"><Empty icon="key" title="Недостаточно прав">Оформление этого документа недоступно вашей роли.</Empty></div>;
  return (
    <div className="inv-page">
      <BackLink to="/inventory/docs" label="Документы" />
      <div className="inv-head"><h1>{meta.doc_kinds[kind]}</h1></div>
      {!init ? <div className="card"><SkelRows rows={4} cols={3} /></div> : <DocEditor init={init} onCancel={() => nav(-1)} onSaved={(d) => nav(`/inventory/docs/${d.id}?new=1`, { replace: true })} />}
    </div>
  );
}

export function DocPage() {
  const { id } = useParams(); const did = Number(id);
  const { meta } = useInv();
  const [d, setD] = useState<DocCard | null>(null); const [err, setErr] = useState(""); const [edit, setEdit] = useState(false);
  const [step, setStep] = useState<string | null>(null);
  const [toast, show] = useToast();
  const [sp] = useSearchParams(); const fresh = sp.get("new") === "1";
  const load = useCallback(() => inv.doc(did).then((x) => { setD(x); setErr(""); }).catch((e) => setErr((e as ApiError).message)), [did]);
  useEffect(() => { void load(); }, [load]);
  if (err) return <div className="card"><Empty icon="file" title="Документ недоступен" action={<Link className="btn" to="/inventory/docs">К документам</Link>}>{err}</Empty></div>;
  if (!d) return <div className="card"><SkelRows rows={6} cols={3} /></div>;
  const draft: Draft = { kind: d.kind, date: d.date, from_location_id: d.from_location_id, to_location_id: d.to_location_id, from_person_id: d.from_person_id, to_person_id: d.to_person_id, resp_id: d.resp_id, basis: d.basis,
    comment: d.comment, data: d.data, items: d.items.filter((i) => i.current).map((i) => ({ asset: i.current!, condition: i.condition, note: i.note })), names: { from_person_id: d.from_person, to_person_id: d.to_person, resp_id: d.resp } };
  const steps = d.kind === "move" ? ["draft", "prepared", "sent", "accepted", "done"] : ["repair", "work", "receipt"].includes(d.kind) ? ["draft", "sent", "done"] : ["draft", "prepared", "done"];
  const data = d.data as Record<string, string>;
  return (
    <div className="inv-page">
      <BackLink to="/inventory/docs" label="Документы" />
      <div className="inv-card-head">
        <div className="inv-card-title"><span className="inv-card-no mono">{d.no}</span><h1>{d.title}</h1>
          <div className="row tight wrap"><span className={`badge ${TONE[d.status]}`}>{d.status_ru}</span><span className="muted small">от {fmtDate(d.date)} · оформил {d.created_by}</span></div></div>
        <div className="row wrap inv-card-actions">
          {d.can.edit && !edit && <button className="btn" onClick={() => setEdit(true)}><Icon name="edit" size={16} />Изменить</button>}
        </div>
      </div>
      {d.status !== "cancelled" && <ol className="inv-steps" aria-label="Этапы документа">{steps.map((s) => {
        const i = steps.indexOf(s), cur = steps.indexOf(d.status);
        return <li key={s} className={i < cur ? "done" : i === cur ? "cur" : ""}><span>{meta.doc_status[s]}</span></li>;
      })}</ol>}
      {!edit && <div className={`card inv-gen ${fresh ? "fresh" : ""}`}><div><h2>Сформировать документ</h2>
        <p className="muted small">{fresh ? "Черновик сохранён. Сформируйте документ для подписи — файл соберётся по текущим данным." : d.status === "draft" ? "Документ ещё черновик: на файле будет отметка «Черновик»." : "Файл собирается по текущим данным документа и шаблону печатной формы."}</p></div>
        <DocFiles id={d.id} /></div>}
      {edit ? <DocEditor init={draft} docId={d.id} onCancel={() => setEdit(false)} onSaved={(x) => { setD(x); setEdit(false); show("Документ сохранён"); }} /> : <>
        {d.next.length > 0 && d.can.move && <div className="card inv-next">
          <div className="row wrap">{d.next.map((s) => <button key={s} className={`btn ${s === "cancelled" || s === "draft" ? "ghost" : "primary"}`} onClick={() => setStep(s)}>{NEXT_LABEL[s] ?? meta.doc_status[s]}</button>)}</div>
          <p className="muted small">{effect(d.kind, d.next.find((s) => s !== "cancelled" && s !== "draft") ?? d.next[0])}</p></div>}
        <div className="split even">
          <div className="card"><h2>Реквизиты</h2>
            <Kv rows={[["Откуда", d.from_location], ["Куда", d.to_location], ["Передаёт / сдаёт", d.from_person], ["Получает", d.to_person], ["Ответственный", d.resp], ["Основание", d.basis],
              ...(d.kind === "repair" ? [["Неисправность", data.fault], ["Исполнитель", data.vendor], ["Результат", data.result], ["Стоимость", data.cost ? `${(Number(data.cost) / 100).toFixed(2)} ₽` : ""], ["Комплектующие", data.parts], ["Возвращено", data.returned_at && fmtDate(data.returned_at)]] as [string, string][] : []),
              ...(d.kind === "work" ? [["Вид работ", meta.work_kinds[data.work_kind] ?? ""], ["Исполнитель", data.executor], ["Срок", data.due && fmtDate(data.due)], ["Описание", data.description], ["Результат", data.result]] as [string, string][] : []),
              ["Примечание", d.comment]]} /></div>
          <div className="card"><h2>Ход документа</h2>
            <ol className="inv-timeline compact">{[...d.history].reverse().map((h, i) => <li key={i}><div className="inv-tl-head"><b>{meta.doc_status[h.to] ?? h.to}</b><span className="muted small">{fmt(h.at)} · {h.by}</span></div>{h.comment && <p className="small muted">{h.comment}</p>}</li>)}</ol></div>
        </div>
        {d.kind === "receipt" && <ReceiptView d={d} />}
        <div className="card flush mt"><div className="card-head"><h2>{d.kind === "receipt" ? `Созданные карточки (${d.items.length})` : `Оборудование (${d.items.length})`}</h2></div>
          <div className="table-scroll"><table className="table compact"><thead><tr><th>Инв. номер</th><th>Наименование</th><th className="hide-sm">Серийный номер</th><th>Состояние</th><th className="hide-sm">Сейчас</th></tr></thead><tbody>
            {d.items.map((i) => <tr key={i.id}><td><Link to={`/inventory/assets/${i.asset_id}`} className="mono">{String(i.snap.inv_no ?? "")}</Link></td><td>{String(i.snap.name ?? "")}<span className="sub">{String(i.snap.model ?? "")}</span></td>
              <td className="hide-sm mono small">{String(i.snap.serial ?? "")}</td><td className="small">{i.condition}{i.note && <span className="sub">{i.note}</span>}</td>
              <td className="hide-sm small">{i.current && <><StBadge st={i.current.st_cls} label={i.current.status} /><span className="sub">{[i.current.user, i.current.location].filter(Boolean).join(" · ")}</span></>}</td></tr>)}</tbody></table></div></div>
      </>}
      {step && <StepDialog d={d} to={step} onClose={() => setStep(null)} onDone={(n) => { setStep(null); void load(); show(n ? `Изменено карточек: ${n}` : "Этап сохранён"); }} />}
      {toast}
    </div>
  );
}

function StepDialog({ d, to, onClose, onDone }: { d: DocCard; to: string; onClose: () => void; onDone: (n: number) => void }) {
  const { meta } = useInv();
  const [comment, setComment] = useState(""); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const [extra, setExtra] = useState<Record<string, unknown>>(to === "done" && d.kind === "repair" ? { returned_at: new Date().toISOString().slice(0, 10) } : {});
  const go = async () => { setBusy(true); setErr(""); try { const r = await inv.docStatus(d.id, to, comment, Object.keys(extra).length ? extra : undefined); onDone(r.changed); } catch (e) { setErr((e as ApiError).message); setBusy(false); } };
  return (
    <Modal title={`${NEXT_LABEL[to] ?? meta.doc_status[to]}: ${d.no}`} lede={effect(d.kind, to)} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Отмена</button><div className="spacer" /><button className={`btn ${to === "cancelled" ? "danger" : "primary"}`} disabled={busy} onClick={() => void go()}>{NEXT_LABEL[to] ?? "Подтвердить"}</button></>}>
      <div className="form-stack">
        {d.kind === "repair" && to === "done" && <>
          <label className="field">Результат ремонта<input value={String(extra.result ?? "")} onChange={(e) => setExtra({ ...extra, result: e.target.value })} placeholder="что сделано" /></label>
          <div className="row wrap"><label className="field">Дата возврата<input type="date" value={String(extra.returned_at ?? "")} onChange={(e) => setExtra({ ...extra, returned_at: e.target.value })} /></label>
            <label className="field">Стоимость, ₽<input inputMode="decimal" value={String(extra.cost ?? "")} onChange={(e) => setExtra({ ...extra, cost: e.target.value })} /></label></div>
          <label className="field">Использованные комплектующие<input value={String(extra.parts ?? "")} onChange={(e) => setExtra({ ...extra, parts: e.target.value })} /></label>
          <RefSelect kind="status" label="Статус после возврата" value={(extra.status_id as number) ?? null} onChange={(v) => setExtra({ ...extra, status_id: v })} empty="прежний" /></>}
        {d.kind === "work" && to === "done" && <label className="field">Результат<input value={String(extra.result ?? "")} onChange={(e) => setExtra({ ...extra, result: e.target.value })} /></label>}
        <label className="field">Комментарий<input value={comment} onChange={(e) => setComment(e.target.value)} maxLength={1000} /></label>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      </div>
    </Modal>
  );
}

interface PrintForm { title: string; no: string; date: string; org: string; org_full: string; unit: string; intro: string; footer: string; parties: [string, string][]; columns: [string, string][]; rows: Record<string, string>[];
  signatures: [string, string][]; comment: string; status: string; draft: boolean }

/** Печатная форма в приложении: тот же состав, что у PDF и DOCX (структура — с сервера), лист A4; при печати меню и шапка скрываются. */
export function DocPrint() {
  const { id } = useParams(); const did = Number(id);
  const [p, setP] = useState<PrintForm | null>(null); const [err, setErr] = useState("");
  useEffect(() => { inv.printForm(did).then((x) => setP(x as unknown as PrintForm)).catch((e) => setErr((e as ApiError).message)); }, [did]);
  if (err) return <div className="card"><Empty icon="file" title="Печатная форма недоступна">{err}</Empty></div>;
  if (!p) return <div className="card"><SkelRows rows={8} cols={3} /></div>;
  return (
    <div className="inv-print-wrap">
      <div className="row wrap inv-print-bar no-print"><BackLink to={`/inventory/docs/${did}`} label="К документу" /><div className="spacer" />
        <DocFiles id={did} noPrint />
        <button className="btn primary" onClick={() => window.print()}><Icon name="file" size={16} />Печать</button></div>
      <article className="inv-sheet">
        {p.org && <div className="inv-sheet-org"><b>{p.org}</b>{p.org_full && p.org_full !== p.org && <span>{p.org_full}</span>}{p.unit && <span>{p.unit}</span>}</div>}
        <h1>{p.title}</h1><p className="inv-sheet-no">№ {p.no} от {p.date}</p>
        {p.draft && <p className="inv-sheet-draft">Документ не проведён · {p.status}</p>}
        {p.parties.length > 0 && <table className="inv-sheet-parties"><tbody>{p.parties.map(([k, v]) => <tr key={k}><td>{k}</td><td>{v}</td></tr>)}</tbody></table>}
        {p.intro && <p>{p.intro}</p>}
        <table className="inv-sheet-items"><thead><tr>{p.columns.map(([k, t]) => <th key={k}>{t}</th>)}</tr></thead>
          <tbody>{p.rows.map((r, i) => <tr key={i}>{p.columns.map(([k]) => <td key={k} className={k === "n" ? "n" : ""}>{r[k]}</td>)}</tr>)}</tbody></table>
        <p className="inv-sheet-total">Всего наименований: {p.rows.length}</p>
        {p.footer && <p>{p.footer}</p>}
        {p.comment && <p>Примечание: {p.comment}</p>}
        <div className="inv-sheet-sigs">{p.signatures.map(([lb, nm], i) => <div key={i}><span className="l">{lb}</span><span className="line">{nm}</span><span className="hint"><span>подпись</span><span>расшифровка подписи</span></span><span className="d">«___» ____________ 20__ г.</span></div>)}</div>
      </article>
    </div>
  );
}

interface Line { type_id: number | null; manufacturer_id: number | null; model_id: number | null; name: string; qty: number; cost: string; warranty_until: string; serials: string[] }

/** Строки поступления: тип или модель, наименование, количество, цена за единицу, гарантия, серийные номера (по одному на единицу, необязательно). */
function ReceiptLines({ d, setData }: { d: { data: Record<string, unknown> }; setData: (k: string, v: unknown) => void }) {
  const { meta } = useInv();
  const lines = ((d.data.lines as Line[] | undefined) ?? []).map((l) => ({ ...l, cost: l.cost === null || l.cost === undefined ? "" : String(l.cost).replace(".", ",") }));
  const set = (i: number, kv: Partial<Line>) => setData("lines", lines.map((l, j) => (j === i ? { ...l, ...kv } : l)));
  const add = () => setData("lines", [...lines, { type_id: null, manufacturer_id: null, model_id: null, name: "", qty: 1, cost: "", warranty_until: "", serials: [] }]);
  const total = lines.reduce((a, l) => a + (Number(l.qty) || 0), 0);
  return (
    <fieldset className="inv-fs"><legend>Строки поступления ({total} ед.)</legend>
      <div className="inv-grid"><label className="field">Поставщик<select value={String(d.data.supplier_id ?? "")} onChange={(e) => setData("supplier_id", e.target.value ? Number(e.target.value) : null)}><option value="">—</option>{meta.refs.filter((r) => r.kind === "supplier").map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}</select></label>
        <label className="field">Документ (счёт, накладная)<input value={String(d.data.invoice ?? "")} onChange={(e) => setData("invoice", e.target.value)} maxLength={300} /></label></div>
      {lines.map((l, i) => <div key={i} className="inv-line">
        <div className="inv-grid">
          <RefSelect kind="type" label="Тип" value={l.type_id} onChange={(v) => set(i, { type_id: v })} />
          <RefSelect kind="manufacturer" label="Производитель" value={l.manufacturer_id} onChange={(v) => set(i, { manufacturer_id: v, model_id: null })} />
          <RefSelect kind="model" label="Модель" parent={l.manufacturer_id} value={l.model_id} onChange={(v) => set(i, { model_id: v })} empty={l.manufacturer_id ? "—" : "сначала производитель"} />
          <label className="field">Наименование<input value={l.name} onChange={(e) => set(i, { name: e.target.value })} maxLength={300} /></label>
          <label className="field">Количество<input type="number" min={1} max={500} value={l.qty} onChange={(e) => set(i, { qty: Math.max(1, Number(e.target.value) || 1) })} /></label>
          <label className="field">Цена за единицу, ₽<input inputMode="decimal" value={l.cost} onChange={(e) => set(i, { cost: e.target.value })} placeholder="0,00" /></label>
          <label className="field">Гарантия до<input type="date" value={l.warranty_until ?? ""} onChange={(e) => set(i, { warranty_until: e.target.value })} /></label>
          <label className="field wide">Серийные номера (по одному в строке, необязательно)<textarea rows={2} value={(l.serials ?? []).join("\n")} onChange={(e) => set(i, { serials: e.target.value.split(/\n|;/).map((x) => x.trim()) })} /></label>
        </div>
        <button type="button" className="btn mini ghost" onClick={() => setData("lines", lines.filter((_, j) => j !== i))}><Icon name="trash" size={14} />Убрать строку</button>
      </div>)}
      <button type="button" className="btn mini" onClick={add}><Icon name="plus" size={14} />Добавить строку</button>
    </fieldset>
  );
}

function ReceiptView({ d }: { d: DocCard }) {
  const { meta } = useInv();
  const lines = (d.data.lines as Line[] | undefined) ?? [];
  const ref = (id: number | null) => meta.refs.find((r) => r.id === id)?.name ?? "";
  return (
    <div className="card flush mt"><div className="card-head"><h2>Строки поступления</h2><span className="muted small">{String(d.data.invoice ?? "")}</span></div>
      <div className="table-scroll"><table className="table compact"><thead><tr><th>Тип</th><th>Производитель и модель</th><th>Наименование</th><th className="num">Кол-во</th><th className="num">Цена, ₽</th><th className="hide-sm">Гарантия до</th></tr></thead>
        <tbody>{lines.map((l, i) => <tr key={i}><td>{ref(l.type_id)}</td><td>{[ref(l.manufacturer_id), ref(l.model_id)].filter(Boolean).join(" ")}</td><td>{l.name}<span className="sub mono">{(l.serials ?? []).join(", ")}</span></td>
          <td className="num">{l.qty}</td><td className="num">{l.cost ?? ""}</td><td className="hide-sm">{l.warranty_until ? fmtDate(l.warranty_until) : ""}</td></tr>)}</tbody></table></div></div>
  );
}
