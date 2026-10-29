import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type KscUserRow } from "../../api";
import type { Ctx } from "../../App";
import { FilterBar } from "../../components/FilterBar";
import { Icon } from "../../components/Icons";
import { ListFoot, useInfinite, useKept } from "../../components/Infinite";
import { personLink } from "../../components/OwnerBlock";
import { QuickReportPanel } from "../../components/QuickReport";
import { Empty, SkelRows } from "../../components/ui";
import { fmt, num } from "../../util";

/** «Пользователи KSC»: учётные записи из списков вошедших (наблюдения KAV Checker). По умолчанию — только Windows: для Linux KSC обычно не передаёт пользователей, фиктивных записей нет. */
export default function KscUsers({ ctx }: { ctx: Ctx }) {
  const [q, setQ] = useKept("ku.q", ""); const [applied, setApplied] = useState(q); const [all, setAll] = useKept("ku.all", false);
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 350); return () => window.clearTimeout(t); }, [q]);
  const list = useInfinite<KscUserRow>(`ku:${ctx.current?.id}:${ctx.all}`, [applied, all], (offset, limit) => api.bi.kscUsers({ q: applied, all_os: all || undefined, offset, limit }), 50);
  const note = (list.extra as { note?: string } | null)?.note;
  const [report, setReport] = useState(false);
  const canReport = ctx.me.user.role !== "viewer";
  return (<>
    <FilterBar search={{ value: q, onChange: setQ, placeholder: "Логин, домен или имя компьютера", label: "Поиск пользователей KSC" }}
      more={<label className="check"><input type="checkbox" className="switch" checked={all} onChange={(e) => setAll(e.target.checked)} />Учитывать все ОС (не только Windows)</label>}
      moreActive={all ? 1 : 0} chips={[...(q ? [{ id: "q", label: `Поиск: ${q}`, onRemove: () => setQ("") }] : []), ...(all ? [{ id: "all", label: "Все ОС", onRemove: () => setAll(false) }] : [])]}
      onReset={() => { setQ(""); setAll(false); }} count={{ n: list.initial ? null : list.total, noun: ["учётная запись", "учётные записи", "учётных записей"] }} onRefresh={() => list.reload()} refreshing={list.refreshing}
      report={canReport ? { onClick: () => setReport(true), disabled: list.initial || !list.total } : null} />
    {report && <QuickReportPanel kind="quick_devices" title="Отчёт: пользователи KSC" lede="Все учётные записи по условиям страницы, с полными списками компьютеров" options={{ scope: false }}
      params={{ view: "users", q: applied || undefined, all_os: all || undefined }} sourceIds={ctx.all ? ctx.sources.map((s) => s.id) : []} activityDays={ctx.me.activity_days} canReport onClose={() => setReport(false)} />}
    {note && <p className="muted small fbar-note">{note}</p>}
    {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
    <div className="table-scroll">
      {list.initial ? <SkelRows cols={5} /> : (
        <table className="table">
          <thead><tr><th>Учётная запись</th><th className="num">Компьютеров</th><th>Компьютеры</th><th className="hide-sm">Последний сеанс (наблюдение)</th><th className="hide-md">Сотрудник по BI</th></tr></thead>
          <tbody>
            {list.items.map((u) => <tr key={u.login}>
              <td className="mono small">{u.domain ? `${u.domain}\\` : ""}{u.login}{u.now && <span className="badge ok">вошёл сейчас</span>}</td>
              <td className="num">{num(u.hosts)}</td>
              <td className="small">{u.host_names.join(", ")}{u.hosts > u.host_names.length && <span className="muted"> +{u.hosts - u.host_names.length}</span>}</td>
              <td className="small nowrap hide-sm">{fmt(u.last_session_at)}</td>
              <td className="small hide-md">{u.bi_person ? <><Link to={personLink(u.bi_person.id)}>{u.bi_person.name}</Link><span className="sub">{u.bi_person.department} · по совпадению логина с почтой</span></> : <span className="muted">—</span>}</td></tr>)}
            {!list.items.length && !list.loading && <tr><td colSpan={5}><Empty icon="users" title="Пользователей нет">{applied ? "Измените запрос." : "KSC ещё не передал списки вошедших пользователей или опрос не выполнялся."}</Empty></td></tr>}
          </tbody>
        </table>)}
    </div>
    <ListFoot list={list} />
  </>);
}
