import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type LdapConn } from "../../api";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { SkelRows, TagInput } from "../../components/ui";

type Rule = { category: string; kind: string; value: string; note: string };
type S = { enabled: boolean; connection: string; ldap_filter: string; day_of_month: number; schedule_time: string; timezone: string; quarter_months: number[]; per_dc_logon: boolean;
  pwd_days: Record<string, number>; inactive_days: number; new_days: number; grace_days: number; protected_users: boolean; admin_groups: string[]; rules: Rule[]; keep_runs: number; events_keep_days: number };
const CATS: [string, string][] = [["user", "Пользователь"], ["admin", "Административная"], ["service", "Сервисная"], ["temp", "Временная"], ["contractor", "Подрядчик"]];
const KINDS: [string, string, string][] = [["group", "Группа", "сильный признак: CN или DN группы, с учётом вложенности"], ["ou", "Подразделение (OU)", "сильный признак: DN ветки каталога"],
  ["attribute", "Атрибут", "сильный признак: атрибут=маска, например employeeType=contractor"], ["name", "Имя (логин)", "слабый признак: маска, например svc*"], ["description", "Описание", "слабый признак: маска, например *сервисн*"]];
const ZONES = ["UTC", "Europe/Moscow", "Europe/Kaliningrad", "Europe/Samara", "Asia/Yekaterinburg", "Asia/Omsk", "Asia/Novosibirsk", "Asia/Krasnoyarsk", "Asia/Irkutsk", "Asia/Yakutsk", "Asia/Vladivostok", "Europe/Minsk", "Asia/Almaty"];

/** «Аудит домена» (администрирование): подключение (существующее LDAPS), расписание, сроки паролей по категориям, пороги активности, правила классификации учётных записей. */
export default function AdAuditAdmin() {
  const [s, setS] = useState<S | null>(null); const [conns, setConns] = useState<LdapConn[]>([]);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [toast, show] = useToast();
  const load = useCallback(() => Promise.all([api.admin.settings("adaudit"), api.admin.ldap.connections()]).then(([x, c]) => { setS(x as unknown as S); setConns(c.items); setErr(""); }).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); }, [load]);
  if (!s) return err ? <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div> : <div className="card"><SkelRows rows={5} cols={4} /></div>;
  const set = <K extends keyof S>(k: K, v: S[K]) => setS({ ...s, [k]: v });
  const setRule = (i: number, r: Partial<Rule>) => set("rules", s.rules.map((x, j) => (j === i ? { ...x, ...r } : x)));
  const save = async () => { setBusy(true); setErr(""); try { setS(await api.admin.saveSettings("adaudit", s as unknown as Record<string, never>) as unknown as S); show("Настройки сохранены: применяются со следующей проверки"); } catch (e) { setErr((e as ApiError).message); } setBusy(false); };
  return (
    <div className="form-stack">
      <div className="card">
        <div className="card-head"><h2>Подключение и расписание</h2><div className="spacer" /><Link className="btn mini" to="/adaudit">Открыть раздел</Link></div>
        <p className="muted small">Раздел использует подключение LDAPS из «Администрирование → LDAPS» и его сервисную учётную запись — только чтение, отдельный пароль не нужен. Учётные записи AD раздел не изменяет.</p>
        <div className="cols">
          <label>Подключение LDAPS<select value={s.connection} onChange={(e) => set("connection", e.target.value)}><option value="">Первое включённое</option>{conns.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label>
          <label>Дополнительный фильтр пользователей<input className="mono" value={s.ldap_filter} onChange={(e) => set("ldap_filter", e.target.value)} placeholder="(!(OU=Archive))" maxLength={500} spellCheck={false} /><span className="help">LDAP-фильтр к фильтру пользователей подключения; пусто — все</span></label>
        </div>
        <label className="check"><input type="checkbox" className="switch" checked={s.enabled} onChange={(e) => set("enabled", e.target.checked)} /><span className="check-body">Ежемесячная проверка по расписанию<span className="help">В квартальные месяцы плановая проверка — квартальная (в её отчёте — неиспользуемые учётные записи и давние пароли)</span></span></label>
        <div className="cols">
          <label>День месяца<input type="number" min={1} max={28} value={s.day_of_month} onChange={(e) => set("day_of_month", Number(e.target.value))} /></label>
          <label>Время<input type="time" value={s.schedule_time} onChange={(e) => set("schedule_time", e.target.value)} /></label>
          <label>Часовой пояс<select value={s.timezone} onChange={(e) => set("timezone", e.target.value)}>{[...new Set([s.timezone, ...ZONES])].map((z) => <option key={z}>{z}</option>)}</select></label>
          <label>Квартальные месяцы<input value={s.quarter_months.join(", ")} onChange={(e) => set("quarter_months", e.target.value.split(/[ ,;]+/).map(Number).filter((n) => n >= 1 && n <= 12))} /><span className="help">Номера месяцев через запятую</span></label>
        </div>
        <label className="check"><input type="checkbox" className="switch" checked={s.per_dc_logon} onChange={(e) => set("per_dc_logon", e.target.checked)} /><span className="check-body">Точная дата последнего входа: опрашивать каждый контроллер домена<span className="help">lastLogon не реплицируется; без опроса используется lastLogonTimestamp (задержка до ~14 суток)</span></span></label>
      </div>
      <div className="card">
        <div className="card-head"><h2>Сроки и пороги</h2></div>
        <div className="cols">{CATS.map(([k, l]) => <label key={k}>Пароль: {l.toLowerCase()}, суток<input type="number" min={1} max={3650} value={s.pwd_days[k] ?? 90} onChange={(e) => set("pwd_days", { ...s.pwd_days, [k]: Number(e.target.value) })} /></label>)}</div>
        <div className="cols">
          <label>Неиспользуемая: без входа, суток<input type="number" min={14} max={3650} value={s.inactive_days} onChange={(e) => set("inactive_days", Number(e.target.value))} /></label>
          <label>Недавно созданная: суток<input type="number" min={1} max={365} value={s.new_days} onChange={(e) => set("new_days", Number(e.target.value))} /></label>
          <label>Срок на первый вход новой учётной записи, суток<input type="number" min={1} max={365} value={s.grace_days} onChange={(e) => set("grace_days", Number(e.target.value))} /></label>
        </div>
        <label className="check"><input type="checkbox" className="switch" checked={s.protected_users} onChange={(e) => set("protected_users", e.target.checked)} /><span className="check-body">Административные учётные записи должны входить в Protected Users</span></label>
        <label>Дополнительные привилегированные группы<TagInput label="Дополнительные привилегированные группы" value={s.admin_groups} onChange={(v) => set("admin_groups", v)} placeholder="CN или DN группы" /><span className="help">К встроенным: Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account/Server/Backup/Print Operators. Членство — с учётом вложенности</span></label>
        <div className="cols">
          <label>Хранить проверок<input type="number" min={3} max={240} value={s.keep_runs} onChange={(e) => set("keep_runs", Number(e.target.value))} /></label>
          <label>Хранить события паролей, суток<input type="number" min={30} max={3650} value={s.events_keep_days} onChange={(e) => set("events_keep_days", Number(e.target.value))} /></label>
        </div>
      </div>
      <div className="card">
        <div className="card-head"><h2>Правила классификации</h2><div className="spacer" /><button className="btn mini" onClick={() => set("rules", [...s.rules, { category: "service", kind: "group", value: "", note: "" }])}><Icon name="plus" size={15} />Правило</button></div>
        <p className="muted small">Категория назначается по одному сильному признаку (группа, OU, атрибут) или по двум согласным слабым (имя, описание, servicePrincipalName). Одно имя или описание — не основание: такая запись попадает в «Не определено» для ручной классификации. Членство в привилегированной группе — всегда административная. Противоречивые сильные признаки — «Не определено».</p>
        <div className="table-scroll"><table className="table compact ada-rules">
          <thead><tr><th>Категория</th><th>Признак</th><th>Значение</th><th>Пояснение</th><th><span className="sr-only">Удалить</span></th></tr></thead>
          <tbody>{s.rules.map((r, i) => (
            <tr key={i}>
              <td><select aria-label="Категория" value={r.category} onChange={(e) => setRule(i, { category: e.target.value })}>{CATS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></td>
              <td><select aria-label="Признак" value={r.kind} onChange={(e) => setRule(i, { kind: e.target.value })} title={KINDS.find((k) => k[0] === r.kind)?.[2]}>{KINDS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></td>
              <td><input aria-label="Значение" className="mono" value={r.value} onChange={(e) => setRule(i, { value: e.target.value })} maxLength={300} spellCheck={false} placeholder={KINDS.find((k) => k[0] === r.kind)?.[2]} /></td>
              <td><input aria-label="Пояснение" value={r.note} onChange={(e) => setRule(i, { note: e.target.value })} maxLength={200} /></td>
              <td><button type="button" className="btn mini ghost danger icon" aria-label="Удалить правило" onClick={() => set("rules", s.rules.filter((_x, j) => j !== i))}><Icon name="trash" size={15} /></button></td>
            </tr>))}</tbody></table></div>
      </div>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="row"><div className="spacer" /><button className="btn primary" aria-busy={busy} onClick={() => void save()}>Сохранить</button></div>
      {toast}
    </div>
  );
}
