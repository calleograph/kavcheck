import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type HierAdmin, type HierCheck, type SettingsValues } from "../../api";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { SkelRows, TagInput } from "../../components/ui";
import { fmt, num } from "../../util";

const STATUS: Record<string, [string, string]> = { ok: ["опубликован", "ok"], failed: ["не удался", "err"], rejected: ["не опубликован", "warn"], running: ["идёт сбор", "accent"] };
const TRIGGER: Record<string, string> = { schedule: "по расписанию", manual: "вручную", upload: "загрузка файла" };
const ROLES: [string, string][] = [["viewer", "Наблюдатель"], ["analyst", "Аналитик"], ["admin", "Администратор (всегда)"]];
const ZONES = ["UTC", "Europe/Moscow", "Europe/Kaliningrad", "Europe/Samara", "Asia/Yekaterinburg", "Asia/Omsk", "Asia/Novosibirsk", "Asia/Krasnoyarsk", "Asia/Irkutsk", "Asia/Yakutsk", "Asia/Vladivostok", "Asia/Magadan", "Asia/Kamchatka", "Europe/Minsk", "Asia/Almaty"];

/** «Иерархия предприятия» (администрирование): источник адресной книги — уже настроенное подключение LDAPS; расписание, роли, правила очистки, названия подразделений, снимки. Правила действуют сразу, без повторного сбора. */
export default function HierarchyAdmin() {
  const [d, setD] = useState<HierAdmin | null>(null);
  const [s, setS] = useState<SettingsValues | null>(null);
  const [map, setMap] = useState<Record<string, string>>({});
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState("");
  const [check, setCheck] = useState<HierCheck | null>(null);
  const [filter, setFilter] = useState("");
  const [toast, show] = useToast();
  const file = useRef<HTMLInputElement>(null);
  const load = useCallback(() => api.hier.admin().then((x) => { setD(x); setS(x.settings); setMap((x.settings.dept_map as unknown as Record<string, string>) ?? {}); setErr(""); }).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (d && (d.running || d.state.requested)) { const t = window.setTimeout(() => void load(), 6000); return () => window.clearTimeout(t); } }, [d, load]);
  if (!d || !s) return err ? <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div> : <div className="card"><SkelRows rows={5} cols={4} /></div>;
  const set = (k: string, v: string | number | boolean | string[]) => setS({ ...s, [k]: v });
  const list = (k: string) => (s[k] as string[]) ?? [];
  const toggleIn = (k: string, v: string) => set(k, list(k).includes(v) ? list(k).filter((x) => x !== v) : [...list(k), v]);
  const run = async (what: string, fn: () => Promise<void>) => { setBusy(what); setErr(""); try { await fn(); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(""); } };
  const save = () => run("save", async () => { const { dept_map: _m, ...rest } = s; void _m; await api.admin.saveSettings("hier", { ...rest, dept_map: map as unknown as string[] }); show("Настройки сохранены: правила применяются сразу, повторный сбор не нужен"); await load(); });
  const upload = (f: File) => run("upload", async () => { const r = await api.hier.upload(await f.arrayBuffer()); show(r.status === "ok" ? `Файл загружен: ${r.message}` : r.message, r.status === "ok" ? "ok" : "error"); await load(); });
  const last = d.last_ok;
  const seen = new Map(d.depts.map((x) => [x.raw, x.n] as [string, number]));
  Object.keys(map).forEach((k) => { if (!seen.has(k)) seen.set(k, 0); });                       // правила для названий, которых в последней выгрузке нет, остаются в таблице
  const rows = [...seen.entries()]
    .filter(([raw]) => !filter || raw.toLowerCase().includes(filter.toLowerCase())).sort((a, b) => Number(!!map[b[0]]) - Number(!!map[a[0]]) || b[1] - a[1]);
  const sourceLdap = s.source === "ldap";
  return (
    <div className="stack">
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="card">
        <div className="row"><h2>Состояние</h2><div className="spacer" />
          <Link className="btn ghost" to="/hierarchy"><Icon name="sitemap" size={15} />Открыть раздел</Link>
          {sourceLdap && <button type="button" className="btn" disabled={!!busy || d.running || d.state.requested} onClick={() => void run("run", async () => { await api.hier.run(); show("Сбор запрошен: worker начнёт в течение минуты"); await load(); })}><Icon name="refresh" size={15} />{d.running || d.state.requested ? "Идёт сбор…" : "Обновить сейчас"}</button>}</div>
        <dl className="kv compact">
          <div><dt>Последний успешный снимок</dt><dd>{last ? <>{fmt(last.finished_at)} · записей {num(last.raw_n)}, после очистки {num(d.people_n)}{last.errors_n ? `, ошибок по записям ${last.errors_n}` : ""}</> : <span className="muted">снимков ещё нет</span>}</dd></div>
          {d.stats && <div><dt>Структура</dt><dd>верхних руководителей {num(d.stats.heads)}, без руководителя в почте {num(d.stats.lone)} (из них по кругу {num(d.stats.cycles)}, руководитель не найден {num(d.stats.unresolved)})</dd></div>}
          <div><dt>Следующий плановый сбор</dt><dd>{s.enabled && sourceLdap ? (d.state.next_run ? fmt(d.state.next_run) : "назначается…") : <span className="muted">плановый сбор выключен</span>}{d.state.retry_n > 0 && <span className="warn-text"> · после ошибки, повтор {d.state.retry_n} из 3</span>}</dd></div>
        </dl>
        {last?.warnings?.map((w, i) => <div key={i} className="alert warn mt-sm" role="status"><Icon name="alert" /><div className="alert-body">{w}</div></div>)}
      </div>

      <div className="card">
        <h2>Источник адресной книги</h2>
        <p className="muted small">Раздел читает поля «Руководитель», «Должность», «Подразделение» из Active Directory, где хранится адресная книга Exchange, — через <b>уже настроенное подключение LDAPS</b> (<Link to="/admin?tab=ldap">Администрирование → LDAPS</Link>): тот же сервер, сервисная учётная запись только для чтения и доверенные сертификаты. Отдельные логин и пароль здесь не вводятся и не хранятся.
          Подключение к почте по SMTP для этого не подходит: протоколы IMAP, POP3 и SMTP поле «Руководитель» не отдают.</p>
        <div className="seg-line" role="radiogroup" aria-label="Источник">
          <label className="check"><input type="radio" name="hsrc" checked={sourceLdap} onChange={() => set("source", "ldap")} /><span className="check-body">Каталог (LDAPS)<span className="help">Автоматический сбор по расписанию и по кнопке</span></span></label>
          <label className="check"><input type="radio" name="hsrc" checked={!sourceLdap} onChange={() => set("source", "file")} /><span className="check-body">Загруженный файл<span className="help">Проверка правил очистки, работа без каталога: JSON-массив записей адресной книги</span></span></label></div>
        {sourceLdap ? <>
          <div className="field"><span>Подключения LDAPS</span>
            {!d.connections.length ? <p className="muted small">Подключений нет: добавьте его в разделе «LDAPS».</p> : <div className="seg-line">{d.connections.map((c) => (
              <label className="check" key={c.id}><input type="checkbox" checked={list("ldap_connections").includes(c.id)} onChange={() => toggleIn("ldap_connections", c.id)} /><span className="check-body">{c.name}{!c.enabled && " (выключено)"}<span className="help">{c.host}</span></span></label>))}</div>}
            <span className="help">Ничего не отмечено — читаются все включённые подключения.</span></div>
          <label className="field">Дополнительный фильтр LDAP<input value={String(s.ldap_filter ?? "")} onChange={(e) => set("ldap_filter", e.target.value)} placeholder="например, (!(msExchHideFromAddressLists=TRUE))" className="mono" />
            <span className="help">Добавляется к фильтру пользователей подключения (только записи с адресом). Пусто — без дополнительных условий. Отключённые учётные записи в структуру не попадают.</span></label>
          <div className="row"><button type="button" className="btn" disabled={!!busy} onClick={() => void run("check", async () => setCheck(await api.hier.check()))}><Icon name="plug" size={15} />{busy === "check" ? "Проверка…" : "Проверить подключение и права"}</button>
            <span className="muted small">Читает не больше 200 записей, ничего не меняет.</span></div>
          {check && (check.message ? <div className="alert warn mt-sm" role="status"><Icon name="alert" /><div className="alert-body">{check.message}</div></div> : check.items.map((it) => (
            <div key={it.name} className={`alert ${it.ok ? "ok" : "error"} mt-sm`} role="status"><Icon name={it.ok ? "checkCircle" : "alert"} /><div className="alert-body"><b>{it.name}</b>: {it.ok ? "подходит для построения структуры" : "структуру построить нельзя"}
              <ul className="small">{it.steps.map((x, i) => <li key={i}><b>{x.name}</b> — {x.text}</li>)}</ul></div></div>)))}
        </> : <div className="row"><input ref={file} type="file" accept=".json,application/json" hidden onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ""; if (f) void upload(f); }} />
          <button type="button" className="btn primary" disabled={!!busy} onClick={() => file.current?.click()}><Icon name="upload" size={15} />{busy === "upload" ? "Загрузка…" : "Загрузить файл выгрузки"}</button>
          <span className="muted small">Те же очистка и публикация, что и при сборе из каталога; порог сокращения для ручной загрузки не применяется.</span></div>}
      </div>

      <div className="card">
        <h2>Расписание и хранение</h2>
        <label className="check"><input type="checkbox" className="switch" checked={!!s.enabled} onChange={(e) => set("enabled", e.target.checked)} /><span className="check-body">Собирать по расписанию<span className="help">Раз в сутки; после ошибки сбор повторяется через 30 минут (до трёх раз). Два сбора одновременно не запускаются</span></span></label>
        <div className="cols">
          <label className="field">Время сбора<input type="time" value={String(s.schedule_time ?? "02:30")} onChange={(e) => set("schedule_time", e.target.value)} /></label>
          <label className="field">Часовой пояс<input list="hier-tz" value={String(s.timezone ?? "UTC")} onChange={(e) => set("timezone", e.target.value)} /><datalist id="hier-tz">{ZONES.map((z) => <option key={z} value={z} />)}</datalist></label></div>
        <div className="cols">
          <label className="field">Хранить снимки, суток<input type="number" min={7} max={3650} value={Number(s.keep_days ?? 90)} onChange={(e) => set("keep_days", Number(e.target.value))} /><span className="help">Последний успешный снимок не удаляется никогда</span></label>
          <label className="field">Порог сокращения выгрузки, %<input type="number" min={0} max={90} value={Number(s.drop_threshold_pct ?? 10)} onChange={(e) => set("drop_threshold_pct", Number(e.target.value))} /><span className="help">Записей меньше, чем в прошлом снимке, на столько процентов — снимок не публикуется, пользователи видят прежний. 0 — не проверять</span></label></div>
      </div>

      <div className="card">
        <h2>Кто видит раздел</h2>
        <p className="muted small">В разделе — персональные данные сотрудников. Права проверяются на сервере: пользователь без выбранной роли не видит пункт меню и не получает данные прямым запросом. Открытия раздела и сборы записываются в журналы.</p>
        <div className="seg-line">{ROLES.map(([r, l]) => <label className="check" key={r}><input type="checkbox" checked={r === "admin" || list("roles").includes(r)} disabled={r === "admin"} onChange={() => toggleIn("roles", r)} /><span className="check-body">{l}</span></label>)}</div>
      </div>

      <div className="card">
        <h2>Правила очистки</h2>
        <p className="muted small">Выгрузка хранится как собрана, правила применяются при показе и действуют сразу. Исключения считаются по первой сработавшей причине.</p>
        <label className="field">Внутренние домены<TagInput label="Внутренние домены" value={list("internal_domains")} onChange={(v) => set("internal_domains", v)} placeholder="example.local" />
          <span className="help">Адреса вне этих доменов исключаются (внешние контакты). Пусто — внешние адреса не исключаются.{d.domains.length > 0 && <> Встречаются в выгрузке: {d.domains.map((x) => <button key={x.domain} type="button" className="link-btn" onClick={() => !list("internal_domains").includes(x.domain) && set("internal_domains", [...list("internal_domains"), x.domain])}>{x.domain} ({num(x.n)})</button>).reduce<React.ReactNode[]>((a, b, i) => (i ? [...a, ", ", b] : [b]), [])}.</>}</span></label>
        <label className="check"><input type="checkbox" className="switch" checked={!!s.drop_empty} onChange={(e) => set("drop_empty", e.target.checked)} /><span className="check-body">Исключать пустые карточки<span className="help">Нет ни должности, ни подразделения, ни руководителя (обычно общие ящики)</span></span></label>
        <label className="check"><input type="checkbox" className="switch" checked={!!s.drop_underscore} onChange={(e) => set("drop_underscore", e.target.checked)} /><span className="check-body">Исключать записи, имя которых начинается с «_»<span className="help">Так часто называют рассылки</span></span></label>
        <label className="check"><input type="checkbox" className="switch" checked={!!s.drop_service} onChange={(e) => set("drop_service", e.target.checked)} /><span className="check-body">Исключать служебные записи</span></label>
        {!!s.drop_service && <div className="cols">
          <label className="field">Слова в должности<TagInput label="Слова в должности" mono={false} value={list("service_words")} onChange={(v) => set("service_words", v)} /></label>
          <label className="field">Адрес начинается с<TagInput label="Начало адреса" value={list("service_prefixes")} onChange={(v) => set("service_prefixes", v)} /></label></div>}
        <label className="check"><input type="checkbox" className="switch" checked={!!s.name_lookup} onChange={(e) => set("name_lookup", e.target.checked)} /><span className="check-body">Искать руководителя по ФИО<span className="help">Если адрес руководителя не указан, а имя заполнено: связь строится только при единственном совпадении</span></span></label>
      </div>

      <div className="card">
        <h2>Правила отчётов-проверок</h2>
        <p className="muted small">Отчёты «Должности и роль», «Руководители» и «Подразделения и подчинённость» подсказывают, что проверить: решение всегда за человеком. Слова ищутся в должности без учёта регистра.</p>
        <div className="cols">
          <label className="field">Должность предполагает руководство<TagInput label="Руководящие слова" mono={false} value={list("lead_words")} onChange={(v) => set("lead_words", v)} /></label>
          <label className="field">Должность обычно неруководящая<TagInput label="Неруководящие слова" mono={false} value={list("nonlead_words")} onChange={(v) => set("nonlead_words", v)} /></label></div>
        <label className="field">Большая группа: больше … непосредственных подчинённых<input type="number" min={3} max={500} value={Number(s.big_group ?? 15)} onChange={(e) => set("big_group", Number(e.target.value))} />
          <span className="help">Повод для проверки, а не ошибка. Подразделения, подчинение которых проверено, отмечаются в карточке сотрудника ({list("reviewed").length} отметок).</span></label>
      </div>

      <div className="card">
        <div className="row"><h2>Названия подразделений</h2><div className="spacer" /><input type="search" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Фильтр" aria-label="Фильтр подразделений" style={{ maxWidth: 220 }} /></div>
        <p className="muted small">В почте одно подразделение часто записано по-разному («ИТ» и «Отдел информационных технологий»). Укажите, как показывать: исходное значение в выгрузке не меняется, угадывания синонимов нет. Пустое поле — показывать как написано.</p>
        {!rows.length ? <p className="muted small">Подразделений в выгрузке пока нет: сначала выполните сбор или загрузите файл.</p> : <div className="table-scroll"><table className="table compact">
          <thead><tr><th>Как написано в почте</th><th className="num">Человек</th><th>Как показывать</th></tr></thead>
          <tbody>{rows.slice(0, 300).map(([raw, n]) => <tr key={raw}><td>{raw}</td><td className="num">{n ? num(n) : <span className="muted">—</span>}</td>
            <td><input value={map[raw] ?? ""} onChange={(e) => setMap({ ...map, [raw]: e.target.value })} placeholder={raw} aria-label={`Как показывать «${raw}»`} /></td></tr>)}</tbody></table></div>}
      </div>

      <div className="row"><button type="button" className="btn primary" disabled={!!busy} onClick={() => void save()}>{busy === "save" ? "Сохранение…" : "Сохранить настройки"}</button><span className="muted small">Источник, расписание, роли, правила и названия подразделений сохраняются вместе.</span></div>

      <div className="card flush">
        <div className="card-head"><h2>История снимков</h2><span className="muted small">последние 40; публикуется только успешный и не «усохший»</span></div>
        {!d.snapshots.length ? <p className="muted small pad">Сборов ещё не было.</p> : <div className="table-scroll flat"><table className="table compact">
          <thead><tr><th>Начало</th><th>Запуск</th><th>Результат</th><th className="num">Записей</th><th className="num hide-sm">После очистки</th><th className="num hide-sm">Ошибок</th></tr></thead>
          <tbody>{d.snapshots.map((x) => { const [t, c] = STATUS[x.status] ?? [x.status, ""]; return (
            <tr key={x.id}><td className="nowrap">{fmt(x.started_at)}</td><td className="small">{TRIGGER[x.trigger] ?? x.trigger}{x.by && <span className="sub">{x.by}</span>}</td>
              <td className="small"><span className={`badge ${c}`}>{t}</span><span className="sub">{x.message}</span>
                {(x.warnings.length > 0 || x.errors.length > 0) && <details className="others"><summary>Замечания: {x.warnings.length + x.errors.length}</summary><ul>{[...x.warnings, ...x.errors].map((w, i) => <li key={i} className="small">{w}</li>)}</ul></details>}</td>
              <td className="num">{num(x.raw_n)}</td><td className="num hide-sm">{x.kept != null ? num(x.kept) : "—"}</td><td className="num hide-sm">{x.errors_n || "—"}</td></tr>); })}</tbody></table></div>}
      </div>
      {toast}
    </div>
  );
}
