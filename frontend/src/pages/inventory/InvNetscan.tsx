/** Сетевое обнаружение: подсети → задание сканера Pentest (только найти узлы и определить тип) → узлы с типом, ОС и портами → карточки для неучтённых.
 *  Запуск — роль «Безопасность» и выше, область — разрешённые сети Pentest. */
import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { ApiError } from "../../api";
import { Icon } from "../../components/Icons";
import { Empty, Segmented, SkelRows } from "../../components/ui";
import { fmt, num } from "../../util";
import { useInv } from "./InvBits";
import { inv, type NetscanResult, type NetscanState } from "./invApi";

const ACTIVE = ["queued", "running"];
const TONE: Record<string, string> = { done: "ok", partial: "warn", failed: "err", cancelled: "", queued: "accent", running: "accent" };
const ST_RU: Record<string, string> = { queued: "В очереди", running: "Выполняется", done: "Готово", partial: "Готово частично", failed: "Ошибка", cancelled: "Отменено" };

export function Netscan({ show, report }: { show: (m: string, t?: "error") => void; report: (params: Record<string, unknown>) => void }) {
  const { can } = useInv();
  const [sp, setSp] = useSearchParams(); const jobId = sp.get("job") ?? "";
  const [st, setSt] = useState<NetscanState | null>(null); const [err, setErr] = useState("");
  const [subnets, setSubnets] = useState(""); const [okScope, setOkScope] = useState(false); const [okLarge, setOkLarge] = useState(false); const [busy, setBusy] = useState(false);
  const load = useCallback(() => inv.netscan().then((x) => { setSt(x); setErr(""); }).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); }, [load]);
  const running = !!st?.jobs.some((j) => ACTIVE.includes(j.status) || (["done", "partial"].includes(j.status) && !j.ingested));
  useEffect(() => { if (!running) return; const t = window.setInterval(() => void load(), 5000); return () => window.clearInterval(t); }, [running, load]);
  const open = (id: string) => setSp((p) => { p.set("job", id); return p; });
  const start = async () => {
    setBusy(true);
    try { const j = await inv.netscanStart({ subnets, confirm_scope: okScope, confirm_large: okLarge }); show(`Задание поставлено в очередь сканера: адресов ${num(j.targets_n)}`); setOkScope(false); await load(); open(j.id); }
    catch (e) { show((e as ApiError).message, "error"); } finally { setBusy(false); }
  };
  if (err) return <div className="card"><Empty icon="alert" title="Сетевое обнаружение недоступно">{err}</Empty></div>;
  if (!st) return <div className="card"><SkelRows rows={4} cols={4} /></div>;
  return (
    <>
      <div className="split">
        <div className="card"><h2>Найти устройства в сети</h2>
          <p className="muted small">Сканер проверяет, какие адреса отвечают, и по открытым портам и ответам служб определяет тип: компьютер, сервер, принтер или МФУ, сетевое устройство. Найденные узлы сравниваются с учётом — неучтённые попадают в «Расхождения».</p>
          {!st.enabled ? <div className="alert flat warn"><Icon name="info" /><div className="alert-body">Сетевое сканирование отключено администратором (Администрирование → Pentest).</div></div>
            : !st.is_security ? <div className="alert flat"><Icon name="info" /><div className="alert-body">Запуск сканирования доступен роли «Безопасность» и администратору. Результаты прошлых заданий видны ниже.</div></div>
            : <form className="form-stack" onSubmit={(e) => { e.preventDefault(); void start(); }}>
              <label className="field">Подсети и адреса<textarea rows={3} value={subnets} onChange={(e) => setSubnets(e.target.value)} placeholder="192.0.2.0/24, 192.0.2.10-192.0.2.40 — через запятую или с новой строки" className="mono" /></label>
              <p className="muted small">Разрешены сети: <span className="mono">{st.networks.join(", ") || "не заданы"}</span>. Проверяемые порты: <span className="mono">{st.ports.replace(/,/g, ", ")}</span>.</p>
              <label className="check-row inv-check"><input type="checkbox" checked={okScope} onChange={(e) => setOkScope(e.target.checked)} />Сканирование этих адресов согласовано</label>
              <label className="check-row inv-check"><input type="checkbox" checked={okLarge} onChange={(e) => setOkLarge(e.target.checked)} />Подтверждаю запуск на большом числе адресов (от {num(st.large_threshold)})</label>
              <div className="row"><button type="submit" className="btn primary" disabled={busy || !subnets.trim() || !okScope}>{busy ? <span className="spin" /> : <Icon name="play" size={16} />}Запустить обнаружение</button></div>
            </form>}
        </div>
        <div className="card"><h2>Что определяется</h2>
          <ul className="reasons small">
            <li><b>Принтер или МФУ</b> — порты печати 9100, 515, 631 или ответ службы принтера.</li>
            <li><b>Сетевое устройство</b> — ответы служб коммутаторов и маршрутизаторов, Telnet без служб Windows.</li>
            <li><b>Компьютер или сервер Windows</b> — службы 135, 445, 3389; сервер — если есть серверные службы (DNS, LDAP, Kerberos, СУБД, IIS).</li>
            <li><b>Сервер Linux и виртуализации</b> — SSH, серверные службы, управление виртуализацией (8006, 902).</li>
          </ul>
          <p className="muted small">Это оценка по сетевым признакам. MAC-адреса и отпечаток ОС сканер без расширенных сетевых привилегий не определяет — ОС берётся из ответов служб. Сканирует только сканер Pentest, нагрузка ограничена его настройками.</p></div>
      </div>
      <div className="card flush mt"><div className="card-head"><h2>Задания</h2><div className="spacer" /><button className="btn ghost mini" onClick={() => void load()}><Icon name="refresh" size={14} />Обновить</button></div>
        <div className="table-scroll"><table className="table compact"><thead><tr><th>Задание</th><th>Состояние</th><th className="hide-sm">Адресов</th><th className="hide-sm">Ответили</th><th className="hide-sm">Запустил</th><th /></tr></thead><tbody>
          {st.jobs.map((j) => <tr key={j.id} className={j.id === jobId ? "sel" : ""}>
            <td>{j.title}{!j.title.includes(j.targets.slice(0, 40)) && <span className="sub mono">{j.targets.slice(0, 80)}</span>}</td>
            <td><span className={`badge ${TONE[j.status] ?? ""}`}>{ST_RU[j.status] ?? j.status}</span>{ACTIVE.includes(j.status) && <div className="bar inv-ns-bar" aria-label={`Выполнено ${j.pct}%`}><i style={{ width: `${j.pct}%` }} /></div>}
              {ACTIVE.includes(j.status) ? <span className="sub">{j.stage_ru}</span> : ["done", "partial"].includes(j.status) && !j.ingested ? <span className="sub">переносится в учёт…</span> : null}</td>
            <td className="hide-sm num">{num(j.targets_n)}</td><td className="hide-sm num">{num(j.hosts_up)}</td><td className="hide-sm small">{j.created_by}<span className="sub">{fmt(j.created_at)}</span></td>
            <td className="nowrap">{["done", "partial"].includes(j.status) && <button className="btn mini" onClick={() => open(j.id)}>Результаты</button>}</td></tr>)}
          {!st.jobs.length && <tr><td colSpan={6}><Empty icon="search" title="Обнаружение ещё не запускалось">Укажите подсети выше — найденные устройства появятся здесь и в «Объектах источников».</Empty></td></tr>}</tbody></table></div></div>
      {jobId && <Result id={jobId} canCreate={can("create")} show={show} report={report} />}
    </>
  );
}

function Result({ id, canCreate, show, report }: { id: string; canCreate: boolean; show: (m: string, t?: "error") => void; report: (params: Record<string, unknown>) => void }) {
  const [r, setR] = useState<NetscanResult | null>(null); const [err, setErr] = useState(""); const [kind, setKind] = useState("all"); const [unreg, setUnreg] = useState(false); const [busy, setBusy] = useState<number | null>(null);
  const load = useCallback(() => inv.netscanResult(id).then((x) => { setR(x); setErr(""); }).catch((e) => setErr((e as ApiError).message)), [id]);
  useEffect(() => { void load(); }, [load]);
  if (err) return <div className="card mt"><Empty icon="alert" title="Результаты недоступны">{err}</Empty></div>;
  if (!r) return <div className="card mt"><SkelRows rows={5} cols={5} /></div>;
  const rows = r.items.filter((h) => (kind === "all" || h.kind === kind) && (!unreg || !h.asset));
  const create = async (oid: number) => { setBusy(oid); try { await inv.infraMatch(oid, "create"); show("Карточка создана"); await load(); } catch (e) { show((e as ApiError).message, "error"); } finally { setBusy(null); } };
  const kinds = Object.entries(r.by_kind);
  return (
    <div className="card flush mt"><div className="card-head wrap"><h2>Результаты: {r.job.title}</h2><span className="muted small">найдено {num(r.items.length)}, нет в учёте {num(r.unregistered)}</span><div className="spacer" />
      <button className="btn" onClick={() => report({ netscan_job: id })}><Icon name="download" size={16} />Сформировать отчёт</button></div>
      <div className="row wrap inv-ns-filter">
        <Segmented label="Тип узла" value={kind} onChange={setKind} options={[["all", `Все ${r.items.length}`], ...kinds.map(([k, n]) => [k, `${r.items.find((h) => h.kind === k)?.kind_ru ?? k} ${n}`] as [string, string])]} />
        <label className="chip-check"><input type="checkbox" checked={unreg} onChange={(e) => setUnreg(e.target.checked)} />только не в учёте</label></div>
      {!r.job.ingested && <p className="muted small inv-ns-note">Результат ещё переносится в учёт: связь с карточками появится через минуту.</p>}
      <div className="table-scroll"><table className="table compact"><thead><tr><th>Адрес и имя</th><th>Тип</th><th className="hide-sm">ОС</th><th className="hide-sm">Открытые порты</th><th>Учёт</th></tr></thead><tbody>
        {rows.map((h) => <tr key={h.ip}><td><span className="mono">{h.ip}</span>{h.name && <span className="sub">{h.name}</span>}</td><td title={h.why}>{h.kind_ru}<span className="sub muted hide-sm">{h.why}</span></td>
          <td className="hide-sm small">{h.os || <span className="muted">не определена</span>}</td>
          <td className="hide-sm small">{h.ports.length ? <span className="mono">{h.ports.map((p) => p.port).join(", ")}</span> : <span className="muted">ответил, открытых портов из списка нет</span>}</td>
          <td>{h.asset ? <Link to={`/inventory/assets/${h.asset.id}`} className="mono">{h.asset.inv_no}<span className="sub">{h.asset.name}</span></Link>
            : h.can_create && canCreate && h.object_id ? <button className="btn mini" disabled={busy === h.object_id} onClick={() => void create(h.object_id!)}>{busy === h.object_id ? <span className="spin sm" /> : <Icon name="plus" size={14} />}Создать<span className="hide-sm">&nbsp;карточку</span></button>
            : h.object_id ? <Link to={`/inventory/infra?tab=objects&q=${encodeURIComponent(h.ip)}`} className="small">сопоставить вручную</Link> : <span className="muted small">нет в учёте</span>}</td></tr>)}
        {!rows.length && <tr><td colSpan={5}><Empty icon="check" title={r.items.length ? "По выбранному отбору узлов нет" : "Ни один адрес не ответил"} /></td></tr>}</tbody></table></div>
    </div>
  );
}
