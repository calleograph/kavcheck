import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type CatalogOverride, type CatalogState } from "../../api";
import { ConfirmDialog } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Empty, SkelRows } from "../../components/ui";
import { fmt, num } from "../../util";
import RulesAdmin from "./RulesAdmin";

const KIND: Record<string, string> = { merge: "Объединение", split: "Выделение записей", rename: "Переименование" };
const STATUS: Record<string, [string, string]> = { ready: ["построен", "ok"], building: ["строится", "accent"], failed: ["ошибка", "err"], empty: ["не построен", "warn"] };

/** Каталог программ: состояние по источникам, ручные исправления (общие для всех источников) и правила группировки для опытных. */
export default function CatalogAdmin() {
  const [states, setStates] = useState<(CatalogState & { source_id: string; source: string; is_active: boolean })[] | null>(null);
  const [ovs, setOvs] = useState<CatalogOverride[] | null>(null);
  const [del, setDel] = useState<CatalogOverride | null>(null);
  const [toast, show] = useToast();
  const load = useCallback(() => { api.admin.catalog().then((r) => setStates(r.items)).catch(() => setStates([])); api.catalog.overrides().then((r) => setOvs(r.items)).catch(() => setOvs([])); }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (!states?.some((s) => s.status === "building")) return; const t = window.setInterval(load, 4000); return () => window.clearInterval(t); }, [states, load]);
  const rebuild = async (id: string) => { try { await api.admin.catalogRebuild(id); show("Обновление каталога запрошено"); load(); } catch (e) { show((e as ApiError).message, "error"); } };
  return (
    <div className="stack">
      <div className="card flush">
        <div className="card-head"><h2>Состояние каталога</h2><span className="muted small">каталог строится из реестра ПО каждого источника и обновляется сам при изменении данных KSC, порога активности или исправлений</span></div>
        {!states ? <SkelRows rows={2} cols={5} /> : (
          <div className="table-scroll flat"><table className="table">
            <thead><tr><th>Источник</th><th>Состояние</th><th>Построен</th><th className="num">Продуктов</th><th className="num">Установок</th><th className="num">Длительность</th><th><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>{states.map((s) => { const [l, c] = STATUS[s.status] ?? [s.status, ""]; return (
              <tr key={s.source_id}><td><b>{s.source}</b>{!s.is_active && <span className="sub">выключен</span>}</td>
                <td><span className={`badge ${c}`}>{s.status === "building" && <span className="spin sm" />}{l}</span>{s.error && <span className="sub bad-text">{s.error}</span>}{s.status === "building" && s.progress && <span className="sub">{s.progress}</span>}</td>
                <td className="small nowrap">{fmt(s.built_at)}</td><td className="num">{num(s.stats?.products)}</td><td className="num">{num(s.stats?.installs)}</td>
                <td className="num small">{s.duration_ms != null ? `${(s.duration_ms / 1000).toFixed(1).replace(".", ",")} с` : "—"}</td>
                <td className="actions"><button className="btn mini" onClick={() => rebuild(s.source_id)} disabled={s.status === "building"}><Icon name="refresh" size={15} />Обновить</button></td></tr>); })}
              {!states.length && <tr><td colSpan={7}><Empty icon="database" title="Источников нет">Добавьте источник KSC — каталог построится автоматически.</Empty></td></tr>}
            </tbody></table></div>)}
      </div>
      <div className="card flush">
        <div className="card-head"><h2>Ручные исправления</h2>{ovs && <span className="count">{num(ovs.length)}</span>}
          <span className="muted small">добавляются в карточке продукта (раздел «Программы»): объединить, выделить записи, переименовать</span></div>
        {!ovs ? <SkelRows rows={2} cols={4} /> : !ovs.length ? <p className="muted small pad">Исправлений нет: каталог собран автоматически.</p> : (
          <div className="table-scroll flat"><table className="table">
            <thead><tr><th>Исправление</th><th>Что</th><th>Во что</th><th>Автор</th><th><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>{ovs.map((o) => (
              <tr key={o.id}><td>{KIND[o.kind]}{o.note && <span className="sub">{o.note}</span>}</td>
                <td className="small">{o.kind === "split" ? `записи «${o.match_name}»` : o.kind === "merge" ? <Link to={`/software/p/${encodeURIComponent(o.from_key ?? "")}`}>{o.from_key}</Link> : "—"}</td>
                <td className="small">{o.kind === "rename" ? <>«{o.to_name}»{o.to_publisher != null && `, ${o.to_publisher}`}</> : <Link to={`/software/p/${encodeURIComponent(o.to_key)}`}>{o.to_name ?? o.to_key}</Link>}</td>
                <td className="small">{o.created_by}<span className="sub">{fmt(o.created_at)}</span></td>
                <td className="actions"><button className="btn mini ghost danger icon" onClick={() => setDel(o)} aria-label="Отменить исправление"><Icon name="trash" size={15} /></button></td></tr>))}
            </tbody></table></div>)}
      </div>
      <details className="card disclosure-card"><summary><h2>Правила группировки (для опытных)</h2><span className="muted small">SQL LIKE и регулярные выражения: используются в дополнительных настройках проверки версий</span></summary>
        <RulesAdmin /></details>
      {del && <ConfirmDialog title="Отменить исправление?" confirmLabel="Отменить исправление" body={<p>Каталог будет перестроен без этого исправления во всех источниках.</p>} onClose={() => setDel(null)} onConfirm={async () => { await api.catalog.deleteOverride(del.id); load(); }} />}
      {toast}
    </div>
  );
}
