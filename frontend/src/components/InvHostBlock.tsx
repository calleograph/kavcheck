/** Блок «Инвентаризация» в карточке компьютера KSC: учётные сведения связанной карточки (номер, категория, местоположение, владелец, ответственные, статус) и переход к ней;
 *  без связи — карточки с тем же именем (сопоставить) или создание учётной карточки. Технический аудит не меняется. */
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import type { ApiError } from "../api";
import { inv, type Asset } from "../pages/inventory/invApi";
import { fmt } from "../util";
import { Icon } from "./Icons";

export function InvHostBlock({ sid, hid, hostName }: { sid: string; hid: number; hostName: string }) {
  const [d, setD] = useState<Awaited<ReturnType<typeof inv.byHost>> | null>(null); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const nav = useNavigate();
  const load = () => inv.byHost(sid, hid).then((x) => { setD(x); setErr(""); }).catch((e) => setErr((e as ApiError).status === 403 ? "" : (e as ApiError).message));
  useEffect(() => { void load(); }, [sid, hid]); // eslint-disable-line react-hooks/exhaustive-deps
  if (err) return <p className="muted small">Инвентаризация: {err}</p>;
  if (!d || d.hidden) return null;
  const link = async (a: Asset) => { setBusy(true); try { await inv.link(a.id, sid, hid, "сопоставлено из карточки компьютера"); await load(); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); } };
  const create = async () => { setBusy(true); try { const r = await inv.kscImport(sid, [hid]); if (r.ids[0]) nav(`/inventory/assets/${r.ids[0]}`); else await load(); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); } };
  const a = d.asset;
  return (
    <div className="inv-hostblock">
      <div className="inv-hostblock-head"><Icon name="package" size={16} /><b>Инвентаризация</b>{a && <Link className="btn mini" to={`/inventory/assets/${a.id}`}>Учётная карточка<Icon name="chevronR" size={14} /></Link>}</div>
      {a ? <>
        <dl className="kv pairs compact">
          <div><dt>Инвентарный номер</dt><dd className="mono">{a.inv_no}{a.acc_no && <span className="sub">бух. {a.acc_no}</span>}</dd></div>
          <div><dt>Категория и статус</dt><dd>{a.type || a.cls_ru} · {a.status || "—"}{a.ksc_link === "auto" && <span className="sub warn-text">связь предполагается по имени — подтвердите в учётной карточке</span>}</dd></div>
          <div><dt>Местоположение</dt><dd>{a.location || <span className="muted">не указано</span>}{a.loc_detail && <span className="sub">{a.loc_detail}</span>}</dd></div>
          <div><dt>Пользователь · владелец</dt><dd>{[a.user, a.owner].filter(Boolean).join(" · ") || <span className="muted">не указаны</span>}</dd></div>
          <div><dt>Ответственный · МОЛ</dt><dd>{[a.resp, a.mol].filter(Boolean).join(" · ") || <span className="muted">не указаны</span>}</dd></div>
          <div><dt>Учётные сведения изменены</dt><dd>{fmt(a.updated_at)}</dd></div>
        </dl></>
        : <div className="small">
          <p className="muted">Компьютер не связан с учётной карточкой.</p>
          {d.candidates.length > 0 && <ul className="inv-list">{d.candidates.map((c) => <li key={c.id}><Link to={`/inventory/assets/${c.id}`} className="mono">{c.inv_no}</Link><span>{c.label.replace(` (${c.inv_no})`, "")}</span>
            {d.can_link && <button className="btn mini" disabled={busy} onClick={() => void link(c)}>Сопоставить</button>}</li>)}</ul>}
          {d.can_create && <button className="btn mini" disabled={busy} onClick={() => void create()}><Icon name="plus" size={14} />Создать учётную карточку для {hostName}</button>}
        </div>}
    </div>
  );
}
