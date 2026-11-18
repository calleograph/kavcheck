import type { DevSession, DevUser, DeviceCard, HostUser } from "../api";
import { CompactList } from "./CompactList";
import { fmt } from "../util";

export const who = (u: DevUser) => (u.resolved ? (u.domain ? `${u.domain}\\${u.login}` : u.login) : "учётная запись не сопоставлена в KSC");
const KIND: Record<string, string> = { user: "", service: "служебная", system: "системная" };

/** Один пользователь: имя и пометка; «сейчас» выделено. */
export function UserChip({ u }: { u: DevUser }) {
  return <span className={`user-chip ${u.now ? "now" : ""} ${u.resolved ? "" : "muted"}`} title={u.now ? "в списке вошедших при последнем опросе" : u.last_session_at ? `замечен в сеансе ${fmt(u.last_session_at)}` : "входил ранее; даты в KSC нет"}>
    {who(u)}{KIND[u.kind] ? <i> ({KIND[u.kind]})</i> : null}</span>;
}

/** Пользователь в строке списка компьютеров: сейчас в системе, иначе последний замеченный в сеансе. */
export function UserSub({ u }: { u?: HostUser | null }) {
  if (!u) return null;
  return <span className="owner-sub" title={u.now ? "в списке вошедших KSC при последнем опросе" : `последний раз замечен в сеансе ${fmt(u.at)}`}>
    <span className="muted">{u.now ? "сейчас: " : "был: "}</span>{u.login}</span>;
}

/** Кто входил: сейчас, последний замеченный, за 7 суток, ранее. */
export function UsersKv({ d }: { d: DeviceCard }) {
  return (
    <dl className="kv">
      <div><dt>Вошли сейчас</dt><dd>{d.current.length ? d.current.map((u, i) => <span key={i} className="block"><UserChip u={u} /></span>) : "никого (по последнему опросу)"}</dd></div>
      <div><dt>Последний замеченный в сеансе</dt><dd>{d.last_user ? <><UserChip u={d.last_user} /> <span className="muted small">наблюдение {fmt(d.last_user.last_session_at)}</span></> : "не наблюдался: KSC не хранит последнего пользователя, наблюдения только за время работы KAV Checker"}</dd></div>
      <div><dt>За 7 суток ({d.week.length})</dt><dd>{d.week.length ? d.week.map((u, i) => <span key={i} className="block"><UserChip u={u} /></span>) : "—"}</dd></div>
      <div><dt>Входили ранее ({d.history.length})</dt><dd>{d.history.length ? <CompactList items={d.history} max={8} render={(u) => <UserChip u={u} />} /> : "—"}</dd></div>
    </dl>
  );
}

const login = (s: DevSession) => (s.domain ? `${s.domain}\\${s.login}` : s.login);

/** Сеансы по наблюдениям: вход и выход — интервалы между опросами списка вошедших (KSC не хранит времени входа). */
export function SessionsTable({ d, max }: { d: DeviceCard; max?: number }) {
  const rows = max ? d.sessions.slice(0, max) : d.sessions;
  return (
    <>
      {rows.length === 0 ? <p className="muted small">Сеансов не наблюдалось{d.observed_since ? ` с ${fmt(d.observed_since)}` : ""}: учёт сеансов начинается с обновления 0.32.0.</p> : (
        <div className="table-scroll"><table className="table compact">
          <thead><tr><th>Пользователь</th><th>Вход</th><th>Выход</th></tr></thead>
          <tbody>{rows.map((s, i) => <tr key={i}>
            <td><span className={`user-chip ${s.open ? "now" : ""}`}>{login(s)}</span></td>
            <td className="small">{s.start_after ? <>между {fmt(s.start_after)}<span className="sub">и {fmt(s.started_at)}</span></> : <>до {fmt(s.started_at)}<span className="sub muted">вход раньше начала наблюдений</span></>}</td>
            <td className="small">{s.open ? <><span className="badge ok">в системе</span><span className="sub muted">замечен {fmt(s.last_active_at)}</span></> : <>между {fmt(s.last_active_at)}<span className="sub">и {fmt(s.ended_at)}</span></>}</td>
          </tr>)}</tbody>
        </table></div>)}
      <p className="muted small">Время — по опросам списка вошедших KSC{d.polled_at ? ` (последний ${fmt(d.polled_at)})` : ""}: точного времени входа и выхода KSC не хранит, сеанс короче интервала опроса может быть не виден.</p>
    </>
  );
}
