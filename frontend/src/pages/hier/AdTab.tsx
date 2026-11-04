import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { api, type AdGroup, type AdGroupCard, type AdMember, type AdStatus, type AdUserCard, type AdUserGroups, type AdUserRow, type ApiError } from "../../api";
import { Icon } from "../../components/Icons";
import { ReportButton } from "../../components/FilterBar";
import { QuickReportPanel } from "../../components/QuickReport";
import { Empty, Segmented, SkelRows } from "../../components/ui";
import { fmt, num } from "../../util";

/** Вкладка «Active Directory»: поиск пользователей и групп домена, карточка, группы пользователя, участники группы. Три колонки (поиск — карточка — группы или участники), на узком экране друг под другом.
 *  Всё читается с сервера из каталога (только чтение); подробные атрибуты — при открытии карточки. */
export interface AdSel { t: "u" | "g"; ref: string }
type Mode = "users" | "groups";

function useCopy() {
  const [done, setDone] = useState("");
  const copy = (text: string, key: string) => {
    const ok = () => { setDone(key); window.setTimeout(() => setDone((d) => (d === key ? "" : d)), 1500); };
    try { void navigator.clipboard.writeText(text).then(ok, () => setDone("")); } catch { setDone(""); }
  };
  return { done, copy };
}

function CopyBtn({ text, label, k, c }: { text: string; label: string; k: string; c: ReturnType<typeof useCopy> }) {
  if (!text) return null;
  return <button type="button" className="btn mini ghost icon ad-copy" aria-label={`Копировать: ${label}`} title={c.done === k ? "Скопировано" : `Копировать ${label}`} onClick={() => c.copy(text, k)}><Icon name={c.done === k ? "check" : "copy"} size={13} /></button>;
}

const initials = (n: string) => (n.split(/\s+/).slice(0, 2).map((x) => x.charAt(0)).join("") || "?").toUpperCase();

export default function AdTab({ sel, setSel, canReport, activityDays, onOpenPerson, exchangeOk }: { sel: AdSel | null; setSel: (s: AdSel | null) => void; canReport: boolean; activityDays: number; onOpenPerson: (id: string) => void; exchangeOk: boolean }) {
  const [status, setStatus] = useState<AdStatus | null>(null);
  const [mode, setMode] = useState<Mode>("users");
  const [q, setQ] = useState("");
  const [applied, setApplied] = useState("");
  const [rows, setRows] = useState<(AdUserRow | AdGroup)[]>([]);
  const [page, setPage] = useState<{ total: number; has_more: boolean; truncated: boolean; max: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [report, setReport] = useState<{ view: string; group?: string; q?: string } | null>(null);
  const [back, setBack] = useState<AdSel[]>([]);
  const seq = useRef(0);
  const sentinel = useRef<HTMLDivElement>(null);

  const checkStatus = useCallback((refresh = false) => { api.ad.status(refresh).then(setStatus).catch((e) => setStatus({ ok: false, name: "", url: "", base_dn: "", message: (e as ApiError).message })); }, []);
  useEffect(() => checkStatus(), [checkStatus]);

  useEffect(() => { const t = window.setTimeout(() => setApplied(q.trim()), 350); return () => window.clearTimeout(t); }, [q]);       // задержка перед запросом
  const load = useCallback((offset: number, refresh = false) => {
    const n = ++seq.current;
    if (applied.replace(/\*/g, "").length < 3) { setRows([]); setPage(null); setErr(applied ? "Нужно хотя бы 3 символа без звёздочки: так запрос не перегружает контроллер домена." : ""); setBusy(false); return; }
    setBusy(true); setErr("");
    (mode === "users" ? api.ad.users(applied, offset, refresh) : api.ad.groups(applied, offset, refresh))
      .then((r) => { if (n !== seq.current) return; setRows((cur) => (offset ? [...cur, ...r.items] : r.items)); setPage(r); })
      .catch((e) => { if (n === seq.current) { setErr((e as ApiError).message); if (!offset) { setRows([]); setPage(null); } } })
      .finally(() => { if (n === seq.current) setBusy(false); });
  }, [applied, mode]);
  useEffect(() => { load(0); }, [load]);
  useEffect(() => {                                                                  // подгрузка при прокрутке до конца списка
    const el = sentinel.current;
    if (!el || !page?.has_more || busy) return;
    const io = new IntersectionObserver((e) => { if (e[0].isIntersecting) load(rows.length); }, { rootMargin: "120px" });
    io.observe(el);
    return () => io.disconnect();
  }, [page?.has_more, busy, rows.length, load]);

  const open = (s: AdSel) => { if (sel) setBack((b) => [...b.slice(-9), sel]); setSel(s); };
  const goBack = () => { const p = back[back.length - 1]; if (p) { setBack(back.slice(0, -1)); setSel(p); } };

  return (
    <div className="ad">
      <div className="ad-bar">
        <span className={`ad-state ${status ? (status.ok ? "ok" : "bad") : ""}`} role="status">
          <i aria-hidden />{!status ? "Проверка подключения…" : status.ok ? <>Подключено: <b>{status.name}</b>{status.ms !== undefined && <small> · {status.ms} мс</small>}</> : <>Каталог недоступен: {status.message}</>}</span>
        <button type="button" className="btn mini ghost" onClick={() => { checkStatus(true); load(0, true); }}><Icon name="refresh" size={14} />Проверить и обновить</button>
        <div className="spacer" />
        {canReport && <ReportButton onClick={() => setReport(sel?.t === "g" ? { view: "group_members", group: sel.ref } : { view: "users", q: applied.replace(/\*/g, "").length >= 3 ? applied : "" })} title="Отчёты по пользователям, группам и расхождениям с Exchange" />}
      </div>
      <div className="ad-grid">
        <section className="ad-col ad-find card" aria-label="Поиск">
          <Segmented label="Что искать" value={mode} onChange={(v) => { setMode(v); setRows([]); setPage(null); }} options={[["users", "Пользователи"], ["groups", "Группы"]]} />
          <div className="input-icon"><Icon name="search" size={16} />
            <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={mode === "users" ? "ivan*, *иванов*, ivanov@*, *support*" : "Название, CN или DN группы"} aria-label="Поиск в Active Directory" autoFocus /></div>
          <p className="muted small">{mode === "users" ? "ФИО, CN, логин, UPN, почта, подразделение, должность или DN. Без * — начало значения; * заменяет любые символы." : "Название, CN, логин группы или DN целиком."}</p>
          {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
          {busy && !rows.length && <SkelRows rows={5} cols={2} />}
          {page && <div className="ad-count">{num(page.total)} найдено{page.truncated && <span className="warn"> · показаны первые {num(page.max)}: уточните запрос</span>}</div>}
          <ul className="ad-list" aria-label="Результаты">
            {rows.map((r) => {
              const u = mode === "users" ? (r as AdUserRow) : null;
              const g = mode === "groups" ? (r as AdGroup) : null;
              const on = sel?.ref === r.ref;
              return <li key={r.ref}><button type="button" className={`ad-item ${on ? "on" : ""}`} aria-current={on ? "true" : undefined} onClick={() => open({ t: mode === "users" ? "u" : "g", ref: r.ref })}>
                <span className={`ad-av ${u?.disabled ? "off" : ""}`} aria-hidden>{u ? initials(u.name) : <Icon name="users" size={15} />}</span>
                <span className="ad-t"><b>{u ? u.name : g!.cn}</b><span>{u ? [u.login, u.department || u.title].filter(Boolean).join(" · ") : [g!.type, g!.scope].filter(Boolean).join(" · ") || g!.description}</span></span>
                {u?.disabled && <span className="ad-tag off">отключена</span>}</button></li>;
            })}
          </ul>
          {page?.has_more && <div ref={sentinel} className="ad-more">{busy ? <span className="spin sm" /> : <button type="button" className="btn mini" onClick={() => load(rows.length)}>Показать ещё</button>}</div>}
          {!busy && !err && applied.replace(/\*/g, "").length >= 3 && !rows.length && <p className="muted small">Ничего не найдено. Попробуйте маску со звёздочкой: <span className="mono">*{applied.replace(/\*/g, "")}*</span>.</p>}
        </section>

        {!sel ? (
          <section className="ad-col ad-wide card"><Empty icon="users" title="Выберите пользователя или группу">Найдите учётную запись слева. В карточке — свойства и состояние, справа — группы пользователя; из группы можно перейти к её участникам.</Empty></section>
        ) : sel.t === "u" ? (
          <UserView key={sel.ref} refId={sel.ref} open={open} back={back.length ? goBack : undefined} onOpenPerson={exchangeOk ? onOpenPerson : undefined} onReport={canReport ? (v) => setReport(v) : undefined} />
        ) : (
          <GroupView key={sel.ref} refId={sel.ref} open={open} back={back.length ? goBack : undefined} onReport={canReport ? (v) => setReport(v) : undefined} />
        )}
      </div>
      {report && <QuickReportPanel kind="quick_ad" title="Отчёт: Active Directory" lede="Данные читаются из каталога в режиме «только чтение»; выгрузка полная, не только загруженные в браузер строки"
        options={{ scope: false, ad: true }} activityDays={activityDays} canReport={canReport} onClose={() => setReport(null)} params={report} />}
    </div>
  );
}

function Field({ label, value, c, k, children }: { label: string; value?: string; c?: ReturnType<typeof useCopy>; k?: string; children?: ReactNode }) {
  if (!value && !children) return null;
  return <><dt>{label}</dt><dd>{children ?? <span className={label === "DistinguishedName" || label === "UPN" ? "mono small break" : ""}>{value}</span>}{c && k && value && <CopyBtn text={value} label={label} k={k} c={c} />}</dd></>;
}

function UserView({ refId, open, back, onOpenPerson, onReport }: { refId: string; open: (s: AdSel) => void; back?: () => void; onOpenPerson?: (id: string) => void; onReport?: (p: { view: string; group?: string; q?: string }) => void }) {
  const [card, setCard] = useState<AdUserCard | null>(null);
  const [groups, setGroups] = useState<AdUserGroups | null>(null);
  const [nested, setNested] = useState(false);
  const [err, setErr] = useState("");
  const [gerr, setGerr] = useState("");
  const [attrQ, setAttrQ] = useState("");
  const c = useCopy();
  const fetchAll = useCallback((refresh = false) => {
    api.ad.user(refId, refresh).then((r) => { setCard(r); setErr(""); }).catch((e) => setErr((e as ApiError).message));
    api.ad.userGroups(refId, false, refresh).then((r) => { setGroups(r); setGerr(""); }).catch((e) => setGerr((e as ApiError).message));
  }, [refId]);
  useEffect(() => { fetchAll(); }, [fetchAll]);
  const showNested = () => { setNested(true); api.ad.userGroups(refId, true).then(setGroups).catch((e) => { setGerr((e as ApiError).message); setNested(false); }); };
  if (err) return <section className="ad-col ad-wide card"><div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div></section>;
  if (!card) return <section className="ad-col ad-wide card"><SkelRows rows={8} cols={2} /></section>;
  const m = card.main, st = card.state;
  const attrs = card.attributes.filter((a) => !attrQ || `${a.name} ${a.values.join(" ")}`.toLowerCase().includes(attrQ.toLowerCase()));
  return (
    <>
      <section className="ad-col ad-card card" aria-label="Карточка пользователя">
        <div className="ad-head">
          {back && <button type="button" className="btn mini ghost" onClick={back}><Icon name="arrowL" size={14} />Назад</button>}
          <span className={`ad-av lg ${st.disabled ? "off" : ""}`} aria-hidden>{initials(m.name)}</span>
          <div className="ad-hn"><h2>{m.name}</h2><span className="muted">{m.title || "Должность не указана"}{m.department ? ` · ${m.department}` : ""}</span></div>
          <button type="button" className="btn mini ghost icon" aria-label="Обновить карточку" title="Прочитать заново из каталога" onClick={() => fetchAll(true)}><Icon name="refresh" size={14} /></button>
        </div>
        <div className="ad-chips">
          <span className={`ad-tag ${st.disabled ? "off" : "ok"}`}>{st.disabled ? "Отключена" : "Активна"}</span>
          <span className={`ad-tag ${st.locked ? "warn" : ""}`} title={st.locked_basis}>{st.locked ? "Заблокирована" : "Не заблокирована"}</span>
          {st.password_expired && <span className="ad-tag warn">Пароль истёк</span>}
          {st.pwd_never_expires && <span className="ad-tag">Пароль без срока</span>}
          {card.exchange.status === "linked" && card.exchange.person && onOpenPerson && <button type="button" className="btn mini" onClick={() => onOpenPerson(card.exchange.person!.id)}><Icon name="sitemap" size={14} />Открыть в структуре Exchange</button>}
          {card.exchange.status === "linked" && !onOpenPerson && <span className="ad-tag">Есть в структуре Exchange</span>}
          {card.exchange.status === "multiple" && <span className="ad-tag warn" title="Адрес этой учётной записи указан у нескольких сотрудников Exchange">В Exchange — несколько кандидатов</span>}
          {card.exchange.status === "none" && <span className="ad-tag" title="Адрес этой учётной записи не найден среди сотрудников структуры Exchange">Нет в структуре Exchange</span>}
        </div>
        <dl className="ad-dl">
          <Field label="ФИО" value={m.name} c={c} k="name" /><Field label="Имя" value={m.given} /><Field label="Фамилия" value={m.surname} />
          <Field label="Логин (sAMAccountName)" value={m.login} c={c} k="login" /><Field label="CN" value={m.cn} c={c} k="cn" /><Field label="UPN" value={m.upn} c={c} k="upn" /><Field label="Почта" value={m.mail} c={c} k="mail" />
          <Field label="Подразделение" value={m.department} /><Field label="Должность" value={m.title} /><Field label="Компания" value={m.company} /><Field label="Офис" value={m.office} />
          {card.manager && <Field label="Руководитель">{card.manager.ref ? <button type="button" className="link-btn" onClick={() => open({ t: "u", ref: card.manager!.ref })}>{card.manager.name}</button> : card.manager.name}</Field>}
          <Field label="Телефон" value={m.phone} /><Field label="Мобильный" value={m.mobile} /><Field label="Табельный номер" value={m.employee_id} /><Field label="Описание" value={m.description} />
          <Field label="DistinguishedName" value={m.dn} c={c} k="dn" />
        </dl>
        <h3 className="ad-h">Состояние учётной записи</h3>
        <dl className="ad-dl">
          <Field label="Создана" value={st.created ? fmt(st.created) : "нет данных"} /><Field label="Изменена" value={st.changed ? fmt(st.changed) : "нет данных"} />
          <Field label="Пароль изменён" value={st.pwd_last_set ? fmt(st.pwd_last_set) : "нет данных"} /><Field label="Срок учётной записи" value={st.expires ? fmt(st.expires) : "не ограничен"} />
          <Field label="Последний вход">{st.last_logon ? fmt(st.last_logon) : "нет данных"}<small className="muted"> · {st.last_logon_note}</small></Field>
          <Field label="Блокировка" value={`${st.locked ? "заблокирована" : "нет"} (по ${st.locked_basis})`} />
        </dl>
        <details className="ad-attrs"><summary>Все атрибуты AD · {card.attributes.length}{card.hidden_n ? `, скрыто секретных: ${card.hidden_n}` : ""}</summary>
          <div className="input-icon"><Icon name="search" size={15} /><input value={attrQ} onChange={(e) => setAttrQ(e.target.value)} placeholder="Фильтр по имени или значению" aria-label="Фильтр атрибутов" /></div>
          <div className="table-scroll flat"><table className="table compact"><thead><tr><th>Атрибут</th><th>Значение</th></tr></thead>
            <tbody>{attrs.map((a) => <tr key={a.name}><td className="mono small nowrap">{a.name}</td><td className="break">{a.values.map((v, i) => <div key={i}>{v}</div>)}{a.more > 0 && <div className="muted small">и ещё {a.more}</div>}</td></tr>)}</tbody></table></div>
          <p className="muted small">Пароли и производные от них значения не показываются и не попадают в отчёты.</p></details>
      </section>

      <section className="ad-col ad-side card" aria-label="Группы пользователя">
        <div className="ad-sh"><h2>Группы</h2>{onReport && <button type="button" className="btn mini ghost" onClick={() => onReport({ view: "memberships", q: m.login })}><Icon name="file" size={14} />Отчёт</button>}</div>
        {gerr && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{gerr}</div></div>}
        {!groups && !gerr && <SkelRows rows={4} cols={2} />}
        {groups && <>
          <h3 className="ad-h">Непосредственные · {groups.direct.length}</h3>
          <p className="muted small">Способ определения: {groups.direct_basis}. Это не полный перечень эффективного членства.</p>
          <GroupList items={groups.direct} open={open} c={c} />
          {groups.primary && <><h3 className="ad-h">Первичная группа</h3><p className="muted small">Определяется атрибутом primaryGroupID и в memberOf не входит.</p><GroupList items={[groups.primary]} open={open} c={c} /></>}
          <h3 className="ad-h">Вложенное членство</h3>
          {!nested ? <><p className="muted small">Группы, в которые пользователь входит через другие группы. Считает контроллер домена, поэтому запрос выполняется по кнопке.</p>
            <button type="button" className="btn mini" onClick={showNested}>Показать вложенные группы</button></>
            : !groups.nested ? <span className="spin sm" /> : <><p className="muted small">Способ определения: {groups.nested.method}. Без непосредственных и первичной группы{groups.nested.truncated ? "; показаны первые 1000" : ""}.</p>
              {groups.nested.items.length ? <GroupList items={groups.nested.items} open={open} c={c} /> : <p className="muted small">Вложенных групп нет.</p>}</>}
        </>}
      </section>
    </>
  );
}

function GroupList({ items, open, c }: { items: AdGroup[]; open: (s: AdSel) => void; c: ReturnType<typeof useCopy> }) {
  if (!items.length) return <p className="muted small">Нет.</p>;
  return <ul className="ad-groups">{items.map((g) => <li key={g.dn || g.cn}>
    <button type="button" className="ad-gname" disabled={!g.ref} onClick={() => open({ t: "g", ref: g.ref })}><Icon name="users" size={15} /><span><b>{g.cn}</b>{g.description && <small>{g.description}</small>}<small className="mono break">{g.dn}</small></span></button>
    <div className="ad-gmeta">{g.type && <span className="ad-tag">{g.type}</span>}{g.scope && <span className="ad-tag">{g.scope}</span>}
      <CopyBtn text={g.cn} label="CN группы" k={`cn:${g.dn}`} c={c} /><CopyBtn text={g.dn} label="DN группы" k={`dn:${g.dn}`} c={c} /></div></li>)}</ul>;
}

function GroupView({ refId, open, back, onReport }: { refId: string; open: (s: AdSel) => void; back?: () => void; onReport?: (p: { view: string; group?: string; q?: string }) => void }) {
  const [card, setCard] = useState<AdGroupCard | null>(null);
  const [err, setErr] = useState("");
  const [mem, setMem] = useState<AdMember[]>([]);
  const [mp, setMp] = useState<{ total: number; has_more: boolean; truncated: boolean; max: number; basis: string; primary_exists: boolean } | null>(null);
  const [merr, setMerr] = useState("");
  const [busy, setBusy] = useState(false);
  const c = useCopy();
  const fetchAll = useCallback((refresh = false) => { api.ad.group(refId, refresh).then((r) => { setCard(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)); }, [refId]);
  useEffect(() => { fetchAll(); }, [fetchAll]);
  const loadMembers = useCallback((offset: number) => {
    setBusy(true);
    api.ad.members(refId, offset).then((r) => { setMem((cur) => (offset ? [...cur, ...r.items] : r.items)); setMp(r); setMerr(""); }).catch((e) => setMerr((e as ApiError).message)).finally(() => setBusy(false));
  }, [refId]);
  useEffect(() => { loadMembers(0); }, [loadMembers]);
  if (err) return <section className="ad-col ad-wide card"><div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div></section>;
  if (!card) return <section className="ad-col ad-wide card"><SkelRows rows={8} cols={2} /></section>;
  const m = card.main;
  return (
    <>
      <section className="ad-col ad-card card" aria-label="Карточка группы">
        <div className="ad-head">
          {back && <button type="button" className="btn mini ghost" onClick={back}><Icon name="arrowL" size={14} />Назад</button>}
          <span className="ad-av lg" aria-hidden><Icon name="users" size={22} /></span>
          <div className="ad-hn"><h2>{m.cn}</h2><span className="muted">{[m.type, m.scope].filter(Boolean).join(" · ") || "Группа каталога"}</span></div>
          <button type="button" className="btn mini ghost icon" aria-label="Обновить карточку" onClick={() => { fetchAll(true); loadMembers(0); }}><Icon name="refresh" size={14} /></button>
        </div>
        <dl className="ad-dl">
          <Field label="CN" value={m.cn} c={c} k="cn" /><Field label="Имя (sAMAccountName)" value={m.sam} c={c} k="sam" /><Field label="Описание" value={m.description} /><Field label="Почта группы" value={m.mail} />
          <Field label="Тип" value={m.type} /><Field label="Область действия" value={m.scope} /><Field label="Создана" value={m.created ? fmt(m.created) : ""} /><Field label="Изменена" value={m.changed ? fmt(m.changed) : ""} />
          <Field label="Управляется" value={m.managed_by} /><Field label="Заметка" value={m.note} /><Field label="DistinguishedName" value={m.dn} c={c} k="dn" />
        </dl>
        <details className="ad-attrs"><summary>Все атрибуты AD · {card.attributes.length}{card.hidden_n ? `, скрыто секретных: ${card.hidden_n}` : ""}</summary>
          <div className="table-scroll flat"><table className="table compact"><thead><tr><th>Атрибут</th><th>Значение</th></tr></thead>
            <tbody>{card.attributes.map((a) => <tr key={a.name}><td className="mono small nowrap">{a.name}</td><td className="break">{a.values.slice(0, 20).map((v, i) => <div key={i}>{v}</div>)}{(a.values.length > 20 || a.more > 0) && <div className="muted small">… значений больше показанных</div>}</td></tr>)}</tbody></table></div></details>
      </section>
      <section className="ad-col ad-side card" aria-label="Участники группы">
        <div className="ad-sh"><h2>Участники{mp ? ` · ${num(mp.total)}` : ""}</h2>{onReport && <button type="button" className="btn mini ghost" onClick={() => onReport({ view: "group_members", group: refId })}><Icon name="file" size={14} />Отчёт</button>}</div>
        {merr && <div className="alert warn" role="alert"><Icon name="alert" /><div className="alert-body">{merr}</div></div>}
        {mp && <p className="muted small">Непосредственные участники ({mp.basis}). Вложенные группы и пользователи с этой первичной группой{mp.primary_exists ? " (такие есть)" : ""} в список не входят.{mp.truncated ? ` Показаны первые ${num(mp.max)}.` : ""}</p>}
        {busy && !mem.length && <SkelRows rows={4} cols={2} />}
        <ul className="ad-list">{mem.map((u) => <li key={u.dn}><button type="button" className="ad-item" disabled={!u.ref || u.kind === "computer" || u.kind === "contact"} onClick={() => open({ t: u.kind === "group" ? "g" : "u", ref: u.ref })}>
          <span className={`ad-av ${u.disabled ? "off" : ""}`} aria-hidden>{u.kind === "group" ? <Icon name="users" size={15} /> : initials(u.name)}</span>
          <span className="ad-t"><b>{u.name}</b><span>{u.kind === "group" ? "вложенная группа" : [u.login, u.title].filter(Boolean).join(" · ")}</span></span>{u.disabled && <span className="ad-tag off">отключена</span>}</button></li>)}</ul>
        {mp?.has_more && <div className="ad-more"><button type="button" className="btn mini" disabled={busy} onClick={() => loadMembers(mem.length)}>Показать ещё</button></div>}
        {mp && !mem.length && !busy && !merr && <p className="muted small">Непосредственных участников нет.</p>}
      </section>
    </>
  );
}
