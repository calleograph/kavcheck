import { useEffect, useRef, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { ActivityBadge, OnlineBadge } from "./Common";
import { Modal } from "./Dialogs";
import { ListFoot, VirtualRows, useInfinite, type Chunk } from "./Infinite";
import { Empty, SkelRows } from "./ui";
import { fmt } from "../util";

export interface DrawerHost { host_id: number; name: string; ip: string; os: string; group: string; last_connected: string | null; days_since_connection: number | null;
  online?: boolean | null; last_visible?: string | null; versions?: { app_name: string; app_version: string }[]; app_name?: string; app_version?: string }

/** Компьютеры по щелчку на числе или версии — в боковой панели рядом с местом щелчка, а не внизу страницы.
 *  Список бесконечный с виртуализацией; карточка компьютера открывается из панели, «Назад» возвращает к той же панели (её состояние — в адресе страницы). */
export function HostsDrawer({ title, lede, listKey, deps, fetchPage, onClose, activityDays, foot }: {
  title: string; lede?: ReactNode; listKey: string; deps: unknown[]; fetchPage: (offset: number, limit: number) => Promise<Chunk<DrawerHost>>; onClose: () => void;
  activityDays: number; foot?: ReactNode;
}) {
  const scroll = useRef<HTMLDivElement>(null);
  const list = useInfinite<DrawerHost>(listKey, deps, fetchPage, 100);
  useEffect(() => { scroll.current?.focus(); }, []);
  const versions = (h: DrawerHost) => (h.versions ?? (h.app_name ? [{ app_name: h.app_name, app_version: h.app_version ?? "" }] : []));
  return (
    <Modal side title={title} lede={lede} onClose={onClose} scrollRef={scroll}>
      {list.error && list.initial && <div className="alert error" role="alert"><div className="alert-body">{list.error}</div></div>}
      {list.initial ? <SkelRows rows={8} cols={5} /> : !list.items.length ? <Empty icon="monitor" title="Компьютеров нет">По этим условиям установок не найдено.</Empty> : (
        <table className="table compact virt">
          <thead><tr><th>Компьютер</th><th>Онлайн</th><th>Установленная версия</th><th className="hide-sm">ОС</th><th className="hide-sm">Группа KSC</th><th>Подключение к KSC</th></tr></thead>
          <tbody>
            <VirtualRows list={list} colSpan={6} estimate={40} scrollEl={scroll} row={(h) => (
              <tr><td><Link to={`/hosts/${h.host_id}`} className="strong-link">{h.name}</Link><span className="sub mono nowrap">{h.ip || "—"}</span></td>
                <td><OnlineBadge online={h.online} seen={h.last_visible} /></td>
                <td className="mono small">{versions(h).map((v, i) => <span key={i} className="block" title={v.app_name}>{v.app_version}</span>)}</td>
                <td className="small hide-sm">{h.os}</td><td className="small hide-sm">{h.group}</td>
                <td className="nowrap small">{fmt(h.last_connected)}<span className="sub"><ActivityBadge days={h.days_since_connection} activityDays={activityDays} /></span></td></tr>)} />
          </tbody>
        </table>)}
      <ListFoot list={list} scrollEl={scroll} />
      {foot}
    </Modal>
  );
}
