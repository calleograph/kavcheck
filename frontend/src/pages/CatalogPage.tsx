import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type ApiError, type CatalogItem, type CatalogState } from "../api";
import type { Ctx } from "../App";
import { Pager } from "../components/Common";
import { Icon } from "../components/Icons";
import { useToast } from "../components/Toast";
import { Empty, HiddenNote, SkelRows, SortTh } from "../components/ui";
import { fmt, num } from "../util";

/** Строка состояния каталога: когда построен, идёт ли сборка, ошибка; кнопка обновления для аналитика и администратора. */
export function CatalogStateLine({ state, canRebuild, onRebuilt }: { state: CatalogState | null; canRebuild: boolean; onRebuilt?: (s: CatalogState) => void }) {
  const [busy, setBusy] = useState(false);
  const [toast, show] = useToast();
  if (!state) return null;
  const rebuild = async () => { setBusy(true); try { const s = await api.catalog.rebuild(); onRebuilt?.(s); show("Обновление каталога запрошено: обычно занимает до минуты"); } catch (e) { show((e as ApiError).message, "error"); } finally { setBusy(false); } };
  const building = state.status === "building" || (state.requested_at && (!state.started_at || state.requested_at > state.started_at));
  return (
    <span className="stamp catalog-state" role="status">
      {building ? <><span className="spin" aria-hidden />Каталог обновляется{state.status === "building" && state.progress ? `: ${state.progress}` : "…"}</>
        : state.built_at ? <><Icon name="clock" size={14} />Каталог построен {fmt(state.built_at)}</> : <><Icon name="clock" size={14} />Каталог ещё не построен</>}
      {state.error && <span className="err-text" title={state.error}> · {state.error.length > 80 ? state.error.slice(0, 80) + "…" : state.error}</span>}
      {canRebuild && !building && <button type="button" className="link-btn" onClick={rebuild} aria-busy={busy} disabled={busy}>Обновить</button>}
      {toast}
    </span>
  );
}

const PLATFORM_ICON: Record<string, string> = { Windows: "Win", Linux: "Linux" };

export function CatalogView({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const navigate = useNavigate();
  const [q, setQ] = useState(sp.get("q") ?? "");
  const publisher = sp.get("publisher") ?? "";
  const [platform, setPlatform] = useState("");
  const [components, setComponents] = useState(false);
  const [all, setAll] = useState(false);
  const [sort, setSort] = useState("hosts"); const [desc, setDesc] = useState(true);
  const [applied, setApplied] = useState(q);
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ items: CatalogItem[]; total: number; state: CatalogState } | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [tick, setTick] = useState(0);
  useEffect(() => { const t = window.setTimeout(() => { setApplied(q); setOffset(0); }, 300); return () => window.clearTimeout(t); }, [q]);
  const urlQ = sp.get("q");   // переход из поиска в верхней панели на уже открытый каталог
  useEffect(() => { if (urlQ !== null) setQ(urlQ); }, [urlQ]);
  useEffect(() => {
    setBusy(true);
    api.catalog.list({ q: applied, publisher, platform, components, all_hosts: all, sort, desc, offset, limit: 50 }).then((r) => { setData(r); setErr(""); })
      .catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
  }, [applied, publisher, platform, components, all, sort, desc, offset, tick]);
  // пока каталог строится — обновляем раз в 5 секунд
  const building = data?.state.status === "building" || data?.state.status === "empty";
  useEffect(() => { if (!building) return; const t = window.setInterval(() => setTick((x) => x + 1), 5000); return () => window.clearInterval(t); }, [building]);
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(k === "hosts" || k === "versions"); } setOffset(0); };
  const canEdit = ctx.me.user.role !== "viewer";
  return (
    <>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Программа, производитель или вариант названия" aria-label="Поиск программы" /></div>
        <select value={platform} onChange={(e) => { setPlatform(e.target.value); setOffset(0); }} aria-label="Платформа" className="w-auto"><option value="">Все платформы</option><option value="windows">Windows</option><option value="linux">Linux</option></select>
        <label className="check inline-check"><input type="checkbox" className="switch" checked={components} onChange={(e) => { setComponents(e.target.checked); setOffset(0); }} />Служебные компоненты</label>
        <div className="toolbar-foot">
          {publisher && <span className="chip">Производитель: <b>{data?.items[0]?.publisher || publisher}</b><button type="button" className="link-btn" onClick={() => setSp((p) => { p.delete("publisher"); return p; })}>сбросить</button></span>}
          <CatalogStateLine state={data?.state ?? null} canRebuild={canEdit} onRebuilt={() => setTick((x) => x + 1)} />
        </div>
      </div>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {data && data.state.status !== "ready" && !data.items.length && (
        <div className="card"><Empty icon="layers" title={data.state.status === "failed" ? "Каталог не построен" : "Каталог программ строится"}
          action={canEdit && data.state.status === "failed" ? <button className="btn" onClick={() => api.catalog.rebuild().then(() => setTick((x) => x + 1))}><Icon name="refresh" />Повторить</button> : undefined}>
          {data.state.status === "failed" ? data.state.error : "Записи реестра KSC объединяются в продукты и ветки. Это происходит в фоне и обычно занимает до минуты; страница обновится сама."}
        </Empty></div>
      )}
      {(data?.items.length || busy || data?.state.status === "ready") ? (
        <div className={`table-scroll ${busy && data ? "is-busy" : ""}`}>
          {!data && busy ? <SkelRows cols={5} /> : (
            <table className="table">
              <thead><tr>
                <SortTh k="name" label="Программа" sort={sort} desc={desc} onSort={onSort} />
                <SortTh k="publisher" label="Производитель" sort={sort} desc={desc} onSort={onSort} className="hide-sm" />
                <th className="hide-sm">Ветки</th>
                <SortTh k="versions" label="Версий" sort={sort} desc={desc} onSort={onSort} className="num" />
                <th className="hide-sm">Новейшая · старейшая</th>
                <SortTh k="hosts" label="Компьютеров" sort={sort} desc={desc} onSort={onSort} className="num" />
                <th><span className="sr-only">Действия</span></th></tr></thead>
              <tbody>
                {(data?.items ?? []).map((p) => (
                  <tr key={p.key} className="clickable" onClick={(e) => { if (!(e.target as HTMLElement).closest("a,button")) navigate(`/software/p/${encodeURIComponent(p.key)}`); }}>
                    <td><Link to={`/software/p/${encodeURIComponent(p.key)}`} className="strong-link">{p.name}</Link>
                      <span className="sub">{p.platforms.map((x) => PLATFORM_ICON[x] ?? x).join(" · ")}{p.origin === "manual" ? " · исправлено вручную" : ""}{p.component ? " · компонент" : ""}</span></td>
                    <td className="small hide-sm">{p.publisher || <span className="muted">—</span>}</td>
                    <td className="hide-sm"><span className="branch-chips">{p.branches.slice(0, 5).map((b) => <span key={b.branch || "-"} className="bchip" title={`${num(b.hosts)} комп.`}>{b.branch || "?"}</span>)}{p.branches.length > 5 && <span className="muted small">+{p.branches.length - 5}</span>}</span></td>
                    <td className="num">{num(p.versions_count)}</td>
                    <td className="mono small nowrap hide-sm">{p.latest_version}{p.oldest_version && p.oldest_version !== p.latest_version ? <span className="muted"> · {p.oldest_version}</span> : null}</td>
                    <td className="num"><b>{num(p.hosts)}</b>{all && p.hidden_hosts > 0 && <span className="sub">{num(p.hidden_hosts)} неакт.</span>}</td>
                    <td className="actions">{canEdit && <Link className="btn mini ghost row-act" to={`/reports?product=${encodeURIComponent(p.key)}&name=${encodeURIComponent(p.name)}${p.latest_version ? `&latest=${encodeURIComponent(p.latest_version)}` : ""}`} title={`Найти устаревшие версии: ${p.name}`}><Icon name="target" size={15} />Проверить</Link>}</td>
                  </tr>))}
                {data && !data.items.length && data.state.status === "ready" && <tr><td colSpan={7}><Empty icon="search" title="Ничего не найдено">Измените запрос или включите служебные компоненты и показ всех устройств.</Empty></td></tr>}
              </tbody>
            </table>)}
        </div>) : null}
      {data && <Pager total={data.total} offset={offset} limit={50} onPage={setOffset} />}
      {data && <HiddenNote hidden={null} days={ctx.me.activity_days} all={all} onToggle={() => { setAll(!all); setOffset(0); }} />}
    </>
  );
}

export function PublishersView({ ctx }: { ctx: Ctx }) {
  const [, setSp] = useSearchParams();
  const [q, setQ] = useState(""); const [applied, setApplied] = useState("");
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<Awaited<ReturnType<typeof api.catalog.publishers>> | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => { const t = window.setTimeout(() => { setApplied(q); setOffset(0); }, 300); return () => window.clearTimeout(t); }, [q]);
  useEffect(() => { api.catalog.publishers({ q: applied, offset, limit: 50 }).then((r) => { setData(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)); }, [applied, offset]);
  const open = (key: string) => setSp((p) => { p.set("tab", "catalog"); p.set("publisher", key); return p; });
  return (
    <>
      <div className="toolbar"><div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Производитель или его программа" aria-label="Поиск производителя" /></div>
        <p className="note">Производители объединяются без учёта формы собственности: «Google LLC» и «Google Inc.» — один производитель. Показаны компьютеры, активные за {ctx.me.activity_days} сут.</p></div>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="table-scroll">
        {!data ? <SkelRows cols={4} /> : (
          <table className="table">
            <thead><tr><th>Производитель</th><th className="num">Продуктов</th><th>Основные продукты</th><th className="num">Компьютеров у самого распространённого</th></tr></thead>
            <tbody>
              {data.items.map((p) => (
                <tr key={p.publisher_key} className="clickable" onClick={() => open(p.publisher_key)}>
                  <td><button type="button" className="link-btn strong-link" onClick={() => open(p.publisher_key)}>{p.publisher}</button></td>
                  <td className="num">{num(p.products)}</td><td className="small">{p.top.join(", ")}</td><td className="num">{num(p.max_hosts)}</td>
                </tr>))}
              {!data.items.length && <tr><td colSpan={4}><Empty icon="search" title="Производители не найдены">Каталог пуст или запрос слишком узкий.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      {data && <Pager total={data.total} offset={offset} limit={50} onPage={setOffset} />}
    </>
  );
}
