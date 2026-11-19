/** Сканирование: камера телефона или планшета (распознавание QR и штрихкодов средствами браузера) либо ручной сканер/ввод → карточка учётной единицы.
 *  Без внешних библиотек: если браузер не умеет распознавать коды, остаётся поле ввода (ручные сканеры работают как клавиатура). */
import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { ApiError } from "../../api";
import { Icon } from "../../components/Icons";
import { KscBadge, StBadge, shortLabel } from "./InvBits";
import { Camera, hasDetector } from "./InvCamera";
import { inv, type Asset } from "./invApi";

export default function InvScan() {
  const [code, setCode] = useState(""); const [hit, setHit] = useState<Asset | null>(null); const [err, setErr] = useState("");
  const [cam, setCam] = useState(false); const [camErr, setCamErr] = useState("");
  const [recent, setRecent] = useState<Asset[]>([]);
  const input = useRef<HTMLInputElement>(null);
  const last = useRef("");
  const find = async (c: string) => {
    const v = c.trim(); if (!v || v === last.current) return;
    last.current = v; setErr("");
    if (v.startsWith("LOC:")) { setErr(`Это этикетка помещения (${v}): она переключает помещение при инвентаризации — раздел «Инвентаризации».`); return; }
    try { const a = await inv.lookup(v); setHit(a); setRecent((r) => [a, ...r.filter((x) => x.id !== a.id)].slice(0, 8)); if (navigator.vibrate) navigator.vibrate(60); }
    catch (e) { setHit(null); setErr((e as ApiError).message); }
    window.setTimeout(() => { last.current = ""; }, 2500);
  };
  return (
    <div className="inv-page inv-scan">
      <div className="inv-head"><h1>Сканирование</h1></div>
      <div className="card">
        <form className="row wrap" onSubmit={(e) => { e.preventDefault(); last.current = ""; void find(code); setCode(""); input.current?.focus(); }}>
          <div className="input-icon grow"><Icon name="search" size={16} /><input ref={input} autoFocus value={code} onChange={(e) => setCode(e.target.value)} placeholder="Отсканируйте этикетку или введите инвентарный / серийный номер" aria-label="Код или номер" /></div>
          <button className="btn primary" type="submit">Найти</button>
          {hasDetector() ? <button type="button" className={`btn ${cam ? "" : "ghost"}`} onClick={() => setCam(!cam)}><Icon name={cam ? "stop" : "eye"} size={16} />{cam ? "Выключить камеру" : "Камера"}</button>
            : <span className="muted small">Распознавание камерой этот браузер не поддерживает — используйте ручной сканер или камеру телефона (QR откроет карточку).</span>}
        </form>
        {camErr && <p className="field-err">{camErr}</p>}
        <Camera on={cam} onCode={(c) => void find(c)} onError={(m) => { setCamErr(m); setCam(false); }} />
        {err && <div className="alert flat warn" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      </div>
      {hit && <div className="card inv-scan-hit" aria-live="polite">
        <span className="inv-card-no mono">{hit.inv_no}</span><h2><Link to={`/inventory/assets/${hit.id}`}>{shortLabel(hit)}</Link></h2>
        <div className="row tight wrap"><StBadge st={hit.st_cls} label={hit.status} /><KscBadge a={hit} /></div>
        <dl className="kv pairs"><div><dt>Местоположение</dt><dd>{hit.location || "не указано"}</dd></div><div><dt>Пользователь</dt><dd>{hit.user || "—"}</dd></div><div><dt>Ответственный</dt><dd>{hit.resp || "—"}</dd></div><div><dt>Серийный номер</dt><dd className="mono">{hit.serial || "—"}</dd></div></dl>
        <Link className="btn primary" to={`/inventory/assets/${hit.id}`}>Открыть карточку</Link>
      </div>}
      {recent.length > 1 && <div className="card"><h2>Отсканировано</h2><ul className="inv-list">{recent.map((a) => <li key={a.id}><Link to={`/inventory/assets/${a.id}`} className="mono">{a.inv_no}</Link><span>{shortLabel(a)}</span><span className="muted small">{a.location}</span></li>)}</ul></div>}
    </div>
  );
}
