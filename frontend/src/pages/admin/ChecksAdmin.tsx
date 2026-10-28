import { useCallback, useEffect, useState } from "react";
import { api, type ApiError, type PtCheck, type PtEngine } from "../../api";
import { ConfirmDialog } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Empty, SkelRows } from "../../components/ui";
import { fmt, num } from "../../util";

const POL: Record<string, [string, string]> = { safe: ["Проверена", "Входит в проверенный набор: только чтение, разрешена по умолчанию."], review: ["Требует утверждения", "Эксплуатационная, подбирающая или воздействующая проверка: разрешается только администратором с подтверждением риска."], forbidden: ["Запрещена", "Не выполняется никогда: DoS, фаззинг, обратные подключения, headless/код, обращения к внешним ресурсам."] };
const IMPACT: Record<string, string> = { passive: "пассивное", low: "низкое", moderate: "умеренное", intrusive: "высокое" };
const SEV: Record<string, string> = { critical: "Критическая", high: "Высокая", medium: "Средняя", low: "Низкая", info: "Информационная", unknown: "—" };
const PAGE = 50;

/** Pentest → Шаблоны и проверки: состояние движка Nuclei и шаблонов (версия, контрольная сумма, обновление/импорт) и каталог проверок Nmap NSE и Nuclei с политикой и решением администратора. */
export default function ChecksAdmin() {
  const [eng, setEng] = useState<PtEngine | null>(null); const [err, setErr] = useState(""); const [toast, show] = useToast();
  const [engine, setEngine] = useState(""); const [category, setCategory] = useState(""); const [policy, setPolicy] = useState(""); const [state, setState] = useState(""); const [q, setQ] = useState(""); const [page, setPage] = useState(0);
  const [data, setData] = useState<{ items: PtCheck[]; total: number; facets: { engine: string; category: string; policy: string; state: string; n: number }[] } | null>(null);
  const [ask, setAsk] = useState<PtCheck | null>(null); const [busy, setBusy] = useState("");
  const loadEng = useCallback(() => api.pentest.engine().then(setEng).catch((e) => setErr((e as ApiError).message)), []);
  const loadList = useCallback(() => api.pentest.checks({ engine, category, policy, state, q, offset: page * PAGE, limit: PAGE }).then(setData).catch((e) => setErr((e as ApiError).message)), [engine, category, policy, state, q, page]);
  useEffect(() => { loadEng(); }, [loadEng]);
  useEffect(() => { const t = window.setTimeout(loadList, 250); return () => window.clearTimeout(t); }, [loadList]);
  useEffect(() => { if (!eng || (eng.status !== "working" && !eng.pending)) return; const t = window.setInterval(() => { loadEng(); loadList(); }, 3000); return () => window.clearInterval(t); }, [eng, loadEng, loadList]);
  const request = async (a: "update" | "import") => { setBusy(a); setErr(""); try { await api.pentest.engineRequest(a); show(a === "update" ? "Запрос на обновление принят: выполнит сканер." : "Запрос на импорт принят: выполнит сканер."); await loadEng(); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(""); } };
  const setCheck = async (c: PtCheck, st: "allowed" | "blocked", risk = false) => {
    await api.pentest.setCheck(c.engine, c.id, st, risk); show(`${st === "allowed" ? "Проверка разрешена" : "Проверка заблокирована"}: ${c.id}`); await loadList(); await loadEng();
  };
  const toggle = (c: PtCheck) => { if (c.state === "allowed") setCheck(c, "blocked").catch((e) => setErr((e as ApiError).message)); else if (c.policy === "review") setAsk(c); else setCheck(c, "allowed").catch((e) => setErr((e as ApiError).message)); };
  const cats = [...new Set((data?.facets ?? []).filter((f) => !engine || f.engine === engine).map((f) => f.category))].sort();
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE)) : 1;
  return (
    <div className="stack">
      {toast}
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <section className="card form">
        <div className="card-head"><h2>Движок Nuclei и шаблоны</h2><div className="spacer" />{eng && <span className={`badge ${eng.ready ? "ok" : "warn"}`}>{eng.ready ? "готов" : "не готов"}</span>}</div>
        {!eng ? <SkelRows rows={3} cols={2} /> : (<>
          <dl className="pt-engine">
            <div><dt>Версия Nuclei</dt><dd>{eng.version || "не установлен"}</dd></div><div><dt>Версия шаблонов</dt><dd>{eng.templates_ver || "не загружены"}</dd></div>
            <div><dt>Шаблонов в каталоге</dt><dd>{num(eng.templates_n)} · разрешено {num(eng.allowed?.nuclei ?? 0)}</dd></div><div><dt>Проверок Nmap NSE</dt><dd>{num(eng.checks?.nse ?? 0)} · разрешено {num(eng.allowed?.nse ?? 0)}</dd></div>
            <div><dt>Источник шаблонов</dt><dd>{eng.templates_source || "—"}</dd></div><div><dt>Загружены</dt><dd>{eng.templates_at ? fmt(eng.templates_at) : "—"}</dd></div>
            <div><dt>Контрольная сумма архива (SHA-256)</dt><dd className="mono small">{eng.templates_sha256 || "—"}</dd></div></dl>
          {eng.message && <p className={eng.status === "error" ? "bad-text" : "muted small"}>{eng.status === "working" ? <span className="spin sm" /> : null} {eng.message}</p>}
          <div className="row">
            <button className="btn" disabled={!!busy || eng.status === "working" || !!eng.pending} onClick={() => request("update")}>{busy === "update" ? <span className="spin" /> : <Icon name="download" />}Обновить шаблоны из релиза</button>
            <button className="btn" disabled={!!busy || eng.status === "working" || !!eng.pending} onClick={() => request("import")}><Icon name="upload" />Импортировать из каталога (офлайн)</button>
          </div>
          <p className="muted small">Шаблоны хранятся локально, Nuclei работает без интернета. Обновление скачивает релиз проекта nuclei-templates (MIT), проверяет контрольную сумму из файла релиза и подпись каждого шаблона при запуске. Новые шаблоны получают решение по политике: автоматически разрешаются только проверенные; изменённые шаблоны, которые вы утвердили вручную, блокируются до повторного утверждения. Офлайн: положите <code>nuclei-templates-*.tar.gz</code> и файл <code>.sha256</code> в каталог импорта сканера.</p>
        </>)}
      </section>
      <section className="card form">
        <h2>Каталог проверок</h2>
        <div className="qr-fields">
          <label className="field">Поиск<input value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} placeholder="Идентификатор, название, описание" /></label>
          <label className="field">Движок<select value={engine} onChange={(e) => { setEngine(e.target.value); setCategory(""); setPage(0); }}><option value="">Все</option><option value="nuclei">Nuclei</option><option value="nse">Nmap NSE</option></select></label>
          <label className="field">Категория<select value={category} onChange={(e) => { setCategory(e.target.value); setPage(0); }}><option value="">Все</option>{cats.map((c) => <option key={c} value={c}>{c}</option>)}</select></label>
          <label className="field">Политика<select value={policy} onChange={(e) => { setPolicy(e.target.value); setPage(0); }}><option value="">Все</option><option value="safe">Проверена</option><option value="review">Требует утверждения</option><option value="forbidden">Запрещена</option></select></label>
          <label className="field">Состояние<select value={state} onChange={(e) => { setState(e.target.value); setPage(0); }}><option value="">Все</option><option value="allowed">Разрешена</option><option value="blocked">Заблокирована</option></select></label>
        </div>
        {!data ? <SkelRows rows={8} cols={7} /> : !data.items.length ? <Empty icon="search" title="Проверок нет">Измените условия поиска или загрузите шаблоны.</Empty> : (
          <div className="table-scroll"><table className="table compact">
            <thead><tr><th>Движок</th><th>Категория</th><th>Проверка</th><th>Критичность</th><th>Протокол</th><th>Воздействие</th><th>Политика</th><th>Состояние</th><th>Обновлена</th></tr></thead>
            <tbody>{data.items.map((c) => (
              <tr key={`${c.engine}:${c.id}`}>
                <td>{c.engine === "nuclei" ? "Nuclei" : "Nmap NSE"}</td><td className="small">{c.category_ru || c.category}</td>
                <td><span className="mono strong">{c.id}</span><span className="sub">{c.name}</span>{c.description && <span className="sub muted" title={c.description}>{c.description.slice(0, 140)}{c.description.length > 140 ? "…" : ""}</span>}</td>
                <td className="small">{SEV[c.severity] ?? c.severity}</td><td className="small mono">{c.protocols}</td><td className="small">{IMPACT[c.impact] ?? c.impact}{c.requests ? <span className="sub">{num(c.requests)} запр.</span> : null}</td>
                <td><span className={`pt-pol ${c.policy}`} title={`${POL[c.policy][1]} ${c.policy_reason}`}>{POL[c.policy][0]}</span></td>
                <td><button type="button" className={`btn mini ${c.state === "allowed" ? "" : "ghost"}`} disabled={c.policy === "forbidden"} onClick={() => toggle(c)} aria-pressed={c.state === "allowed"}
                  title={c.decided_by ? `Решение: ${c.decided_by}` : "Решение по политике"}>{c.state === "allowed" ? "Разрешена" : "Заблокирована"}</button></td>
                <td className="small">{fmt(c.updated_at)}</td>
              </tr>))}</tbody></table></div>)}
        {data && <div className="row"><span className="muted small">Найдено: {num(data.total)} · страница {page + 1} из {pages}</span><div className="spacer" />
          <button className="btn mini" disabled={page === 0} onClick={() => setPage(page - 1)}>Назад</button><button className="btn mini" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Вперёд</button></div>}
      </section>
      {ask && <ConfirmDialog title="Разрешить проверку, требующую утверждения" confirmLabel="Разрешить с подтверждением риска" danger onClose={() => setAsk(null)} onConfirm={() => setCheck(ask, "allowed", true)}
        body={<><p><b className="mono">{ask.id}</b> — {ask.name}</p><p>{ask.policy_reason}</p><p>Проверка будет выполняться только в заданиях с включённой галочкой «Дополнительные активные проверки». Подтверждая, вы отвечаете за разрешение проверять эти системы такими запросами. Решение записывается в журнал действий.</p></>} />}
    </div>
  );
}
