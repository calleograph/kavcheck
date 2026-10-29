import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { BiOwnerBrief } from "../api";
import { ActivityBadge, OnlineBadge } from "./Common";
import { Modal } from "./Dialogs";
import { ReportButton } from "./FilterBar";
import { Icon } from "./Icons";
import { ListFoot, VirtualRows, useInfinite, type Chunk } from "./Infinite";
import { Empty, MaskHint, SkelRows, SortTh } from "./ui";
import { fmt, num, plural } from "../util";

export interface DrawerHost { host_id: number; name: string; ip: string; os: string; group: string; last_connected: string | null; days_since_connection?: number | null;
  online?: boolean | null; last_visible?: string | null; versions?: { app_name: string; app_version: string }[]; app_name?: string; app_version?: string;
  source_id?: string; source?: string; zones?: string[]; active?: boolean; note?: ReactNode; owner?: BiOwnerBrief | null }

export interface PanelQuery { q: string; sort: string; desc: boolean }

/** Единая боковая панель устройств: открывается по щелчку на числе («Устройств», «Затронуто компьютеров», «Установки»…) в любом разделе.
 *  Серверные поиск, сортировка и постраничная выдача (бесконечный список с виртуализацией); имя ведёт в карточку устройства; Escape и крестик закрывают.
 *  Кнопка «Сформировать отчёт» запускает единый конструктор именно по этим устройствам. Состояние панели — в адресе страницы (кнопка «Назад» возвращает сюда). */
export function HostsDrawer({ title, lede, listKey, deps, fetchPage, onClose, activityDays, foot, search, sortKeys, report, versions: showVersions, multiSource, defaultSort = "name" }: {
  title: string; lede?: ReactNode; listKey: string; deps: unknown[]; fetchPage: (offset: number, limit: number, query: PanelQuery) => Promise<Chunk<DrawerHost>>; onClose: () => void;
  activityDays: number; foot?: ReactNode;
  search?: string;                                              // подсказка поля поиска; без неё поиска в панели нет (сервер списка его не поддерживает)
  sortKeys?: Partial<Record<"name" | "ip" | "os" | "group" | "last_connected", string>>;   // какие столбцы сортируются на сервере и под каким ключом
  report?: { onClick: () => void; disabled?: boolean; title?: string } | null;
  versions?: boolean;                                           // столбец «Установленная версия» (списки по программам)
  multiSource?: boolean;                                        // столбец «Источник KSC» и ссылки в карточку «Устройств» (режим «Все источники»)
  defaultSort?: string;
}) {
  const scroll = useRef<HTMLDivElement>(null);
  const [q, setQ] = useState(""); const [applied, setApplied] = useState("");
  const [sort, setSort] = useState(defaultSort); const [desc, setDesc] = useState(false);
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 300); return () => window.clearTimeout(t); }, [q]);
  const list = useInfinite<DrawerHost>(listKey, [...deps, applied, sort, desc], (offset, limit) => fetchPage(offset, limit, { q: applied, sort, desc }), 100);
  useEffect(() => { scroll.current?.focus(); }, []);
  const vers = (h: DrawerHost) => (h.versions ?? (h.app_name ? [{ app_name: h.app_name, app_version: h.app_version ?? "" }] : []));
  const withVersions = showVersions ?? list.items.some((h) => vers(h).length > 0);
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(false); } };
  const th = (k: keyof NonNullable<typeof sortKeys>, label: string, cls = "") => (sortKeys?.[k] ? <SortTh k={sortKeys[k]!} label={label} sort={sort} desc={desc} onSort={onSort} className={cls} /> : <th className={cls}>{label}</th>);
  const hasState = list.items.some((h) => h.online !== undefined || h.active !== undefined);        // столбец «Состояние» только если источник списка отдаёт признак сети или активности
  const cols = 4 + (hasState ? 1 : 0) + (withVersions ? 1 : 0) + (multiSource ? 1 : 0);
  const cardLink = (h: DrawerHost) => (h.source_id ? `/devices?card=${h.source_id}:${h.host_id}` : `/hosts/${h.host_id}`);
  return (
    <Modal side title={title} lede={lede} onClose={onClose} scrollRef={scroll}>
      <div className="dp-bar">
        {search !== undefined && <div className="input-icon dp-search"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder={search || "Имя компьютера или адрес"} aria-label="Поиск по списку устройств" /><MaskHint /></div>}
        <span className="dp-count" role="status" aria-live="polite">{list.initial ? "…" : <><b>{num(list.total)}</b> <span className="muted">{plural(list.total, "устройство", "устройства", "устройств")}</span></>}</span>
        {report && <ReportButton {...report} title={report.title ?? "Сформировать отчёт по устройствам этого списка"} />}
      </div>
      {list.error && list.initial && <div className="alert error" role="alert"><div className="alert-body">{list.error}</div></div>}
      {list.initial ? <SkelRows rows={8} cols={5} /> : !list.items.length ? <Empty icon="monitor" title="Устройств нет">{applied ? "По этому запросу в списке ничего не найдено." : "По этим условиям устройств не найдено."}</Empty> : (
        <table className="table compact virt">
          <thead><tr>{th("name", "Компьютер")}{hasState && <th>Состояние</th>}{withVersions && <th>Установленная версия</th>}{th("os", "ОС", "hide-sm")}{th("group", multiSource ? "Группа и зоны" : "Группа KSC", "hide-sm")}
            {multiSource && <th className="hide-sm">Источник</th>}{th("last_connected", "Подключение к KSC")}</tr></thead>
          <tbody>
            <VirtualRows list={list} colSpan={cols} estimate={44} scrollEl={scroll} row={(h) => (
              <tr><td><Link to={cardLink(h)} className="strong-link">{h.name}</Link><span className="sub mono nowrap">{h.ip || "—"}</span>
                {h.owner && <span className="owner-sub" title={h.owner.state_ru}>{h.owner.multi ? "владельцы: несколько" : h.owner.name}{h.owner.department && <span className="muted"> · {h.owner.department}</span>}{h.owner.state !== "current" && <span className="muted"> ({h.owner.state_ru.toLowerCase()})</span>}</span>}</td>
                {hasState && <td>{h.online !== undefined ? <OnlineBadge online={h.online} seen={h.last_visible ?? null} /> : <span className="muted small">{h.active === false ? "давно не подключался" : h.active ? "активен" : "—"}</span>}</td>}
                {withVersions && <td className="mono small">{vers(h).map((v, i) => <span key={i} className="block" title={v.app_name}>{v.app_version}</span>)}</td>}
                <td className="small hide-sm">{h.os || "—"}</td><td className="small hide-sm">{[h.group, ...(h.zones ?? [])].filter(Boolean).join(" · ") || "—"}</td>
                {multiSource && <td className="small hide-sm">{h.source ?? ""}</td>}
                <td className="nowrap small">{fmt(h.last_connected)}{h.days_since_connection !== undefined && <span className="sub"><ActivityBadge days={h.days_since_connection} activityDays={activityDays} /></span>}{h.note}</td></tr>)} />
          </tbody>
        </table>)}
      <ListFoot list={list} scrollEl={scroll} />
      {foot}
    </Modal>
  );
}
