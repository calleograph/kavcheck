import { useEffect, useMemo, useRef, useState } from "react";
import { api, type ApiError, type HuntCriterion, type HuntPreview, type HuntProductIn, type HuntScopeIn } from "../../api";
import { Icon } from "../../components/Icons";
import { MultiCheck, Segmented } from "../../components/ui";
import { num } from "../../util";

export type Prefill = { cves: string[]; product?: Partial<HuntProductIn> };
const MODE_RU: [HuntProductIn["mode"], string][] = [["any", "Любая версия"], ["exact", "Конкретные версии"], ["range", "Диапазон"], ["below", "Ниже указанной"], ["above", "Выше указанной"]];
const emptyProduct = (p: Partial<HuntProductIn>): HuntProductIn => ({ name: "", mode: "any", versions: [], v_min: "", v_max: "", below: "", above: "", only_vulnerable: false, only_eol: false, ...p });
const useDebounced = <T,>(v: T, ms = 300) => { const [d, setD] = useState(v); useEffect(() => { const t = window.setTimeout(() => setD(v), ms); return () => window.clearTimeout(t); }, [v, ms]); return d; };

/** Мастер «Новое задание»: что искать (CVE и продукты с условиями), режим и область, порты, предварительная сводка и запуск. Каталог программ и база уязвимостей — общие с остальными разделами. */
export default function Wizard({ prefill, onCreated }: { prefill: Prefill; onCreated: (id: string) => void }) {
  const [opts, setOpts] = useState<Awaited<ReturnType<typeof api.hunt.options>> | null>(null);
  const [cves, setCves] = useState<string[]>(prefill.cves);
  const [products, setProducts] = useState<HuntProductIn[]>(prefill.product?.name ? [emptyProduct(prefill.product)] : []);
  const [q, setQ] = useState(""); const dq = useDebounced(q);
  const [sug, setSug] = useState<Awaited<ReturnType<typeof api.hunt.suggest>> | null>(null);
  const [crits, setCrits] = useState<HuntCriterion[]>([]);
  const [mode, setMode] = useState<"ksc" | "network" | "combined">("combined");
  const [logic, setLogic] = useState<"any" | "all">("any");
  const [scope, setScope] = useState<HuntScopeIn>({ kind: "sources", sources: [], zones: [], group: "", text: "", exclude: "", active_days: 30 });
  const [ports, setPorts] = useState("");
  const [title, setTitle] = useState("");
  const [confirm, setConfirm] = useState(false); const [big, setBig] = useState(false);
  const [pv, setPv] = useState<HuntPreview | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => { api.hunt.options().then((o) => { setOpts(o); setScope((s) => (s.sources.length || !o.sources.length ? s : { ...s, sources: o.sources.map((x) => x.id) })); }).catch((e) => setErr((e as ApiError).message)); }, []);
  useEffect(() => { if (dq.trim().length < 2) { setSug(null); return; } api.hunt.suggest(dq.trim()).then(setSug).catch(() => setSug(null)); }, [dq]);
  const sel = useMemo(() => ({ cves, products }), [cves, products]);
  const key = JSON.stringify(sel);
  useEffect(() => {
    if (!cves.length && !products.length) { setCrits([]); return; }
    let live = true;
    api.hunt.resolve(sel).then((r) => { if (live) { setCrits(r.criteria); setErr(""); } }).catch((e) => { if (live) { setCrits([]); setErr((e as ApiError).message); } });
    return () => { live = false; };
  }, [key]);                                                            // eslint-disable-line react-hooks/exhaustive-deps
  const scopeKey = JSON.stringify([scope, ports, mode]);
  useEffect(() => {
    if (!crits.length) { setPv(null); return; }
    let live = true;
    const t = window.setTimeout(() => { api.hunt.preview({ ...sel, scope, ports }).then((r) => { if (live) { setPv(r); setErr(""); } }).catch((e) => { if (live) { setPv(null); setErr((e as ApiError).message); } }); }, 400);
    return () => { live = false; window.clearTimeout(t); };
  }, [key, scopeKey, crits.length]);                                    // eslint-disable-line react-hooks/exhaustive-deps
  const addCve = (id: string) => { setCves((c) => (c.includes(id) ? c : [...c, id])); setQ(""); setSug(null); };
  const addProduct = (p: { name: string; kb: string; source_id: string; product_key: string }) => { setProducts((l) => [...l, emptyProduct({ name: p.name, kb: p.kb, source_id: p.source_id || undefined, product_key: p.product_key || undefined })]); setQ(""); setSug(null); };
  const typedCve = /^cve-\d{4}-\d{4,7}$/i.test(q.trim()) ? q.trim().toUpperCase() : "";
  const setProd = (i: number, patch: Partial<HuntProductIn>) => setProducts((l) => l.map((p, j) => (j === i ? { ...p, ...patch } : p)));
  const net = mode !== "ksc";
  const noPorts = net && pv && pv.ports.length === 0;
  const large = !!pv && !!opts && pv.targets >= opts.large_threshold;
  const run = async () => {
    setBusy(true); setErr("");
    try { const j = await api.hunt.create({ ...sel, scope, ports, title, logic, mode, confirm_scope: confirm, confirm_large: big }); onCreated(j.id); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); }
  };
  if (!opts) return <div className="card"><span className="skel skel-text" style={{ width: "60%" }} /></div>;
  const count = cves.length + products.length;
  return (
    <div className="stack hunt-wiz">
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <section className="card" ref={box}>
        <h2>Что искать</h2>
        <div className="hunt-search">
          <div className="input-icon grow"><Icon name="search" size={16} />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="CVE-2024-6387, название уязвимости или продукта: PHP, OpenSSH, 1С-Битрикс…" aria-label="Что искать" role="combobox" aria-expanded={!!sug} aria-controls="hunt-sug" autoComplete="off"
              onKeyDown={(e) => { if (e.key === "Enter" && typedCve) { e.preventDefault(); addCve(typedCve); } }} /></div>
          {(sug || typedCve) && (
            <ul id="hunt-sug" className="hunt-sug" role="listbox">
              {typedCve && !sug?.cves.some((c) => c.id === typedCve) && <li role="option"><button type="button" onClick={() => addCve(typedCve)}><b className="mono">{typedCve}</b> <span className="muted">добавить</span></button></li>}
              {(() => {      // название продукта — сначала продукты KSC, идентификатор CVE — сначала уязвимости
                const cvesEl = (sug?.cves.length ?? 0) > 0 && <><li className="hunt-sug-h" role="presentation">Уязвимости</li>{sug?.cves.map((c) => <li role="option" key={c.id}><button type="button" onClick={() => addCve(c.id)}><b className="mono">{c.id}</b>{c.exploited && <span className="badge err">эксплуатируется</span>} <span className="muted">{c.title}</span></button></li>)}</>;
                const prodEl = (sug?.products.length ?? 0) > 0 && <><li className="hunt-sug-h" role="presentation">Продукты в KSC</li>{sug?.products.map((p) => <li role="option" key={`${p.source_id}:${p.product_key}:${p.name}`}><button type="button" onClick={() => addProduct(p)}><Icon name="package" size={14} /> <b>{p.name}</b> <span className="muted">{p.hosts != null ? `компьютеров в KSC: ${num(p.hosts)}` : "известный продукт"}</span></button></li>)}</>;
                return /^\s*(cve|bdu)/i.test(q) ? <>{cvesEl}{prodEl}</> : <>{prodEl}{cvesEl}</>;
              })()}
              {sug && !sug.cves.length && !sug.products.length && !typedCve && <li className="muted small pad">Ничего не найдено: введите полный идентификатор CVE.</li>}
            </ul>)}
        </div>
        {cves.length > 0 && <div className="chips mt">{cves.map((c) => <span key={c} className="chip-x mono">{c}<button type="button" aria-label={`Убрать ${c}`} onClick={() => setCves(cves.filter((x) => x !== c))}><Icon name="close" size={12} /></button></span>)}</div>}
        {products.map((p, i) => (
          <div key={i} className="hunt-prod">
            <div className="row"><b>{p.name}</b><span className="spacer" /><button type="button" className="btn mini ghost" onClick={() => setProducts(products.filter((_, j) => j !== i))}>Убрать</button></div>
            <div className="cols">
              <label>Версии<select value={p.mode} onChange={(e) => setProd(i, { mode: e.target.value as HuntProductIn["mode"] })}>{MODE_RU.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
              {p.mode === "exact" && <label>Список версий<input value={p.versions.join(", ")} onChange={(e) => setProd(i, { versions: e.target.value.split(/[,\s]+/).filter(Boolean) })} placeholder="8.1.12, 8.1.13" /></label>}
              {p.mode === "range" && <><label>От<input value={p.v_min} onChange={(e) => setProd(i, { v_min: e.target.value })} placeholder="8.1.0" /></label><label>До<input value={p.v_max} onChange={(e) => setProd(i, { v_max: e.target.value })} placeholder="8.1.30" /></label></>}
              {p.mode === "below" && <label>Ниже версии<input value={p.below} onChange={(e) => setProd(i, { below: e.target.value })} placeholder="8.2.0" /></label>}
              {p.mode === "above" && <label>Выше версии<input value={p.above} onChange={(e) => setProd(i, { above: e.target.value })} placeholder="8.1" /></label>}
            </div>
            <div className="row gap"><label className="check"><input type="checkbox" checked={p.only_vulnerable} onChange={(e) => setProd(i, { only_vulnerable: e.target.checked })} />Только версии с известными уязвимостями</label>
              <label className="check"><input type="checkbox" checked={p.only_eol} onChange={(e) => setProd(i, { only_eol: e.target.checked })} />Только версии с завершённой поддержкой</label></div>
          </div>))}
        {count > 1 && <div className="row mt"><span className="muted small">Логика:</span><Segmented<"any" | "all"> label="Логика критериев" value={logic} onChange={setLogic} options={[["any", "Любой из критериев"], ["all", "Все критерии"]]} /></div>}
        {count === 0 && <p className="muted small mt">Укажите CVE или продукт. Можно объединять несколько условий в одном задании.</p>}
      </section>

      {crits.length > 0 && <section className="card"><h2>Что известно о критериях</h2>
        <ul className="hunt-crit">{crits.map((c) => (
          <li key={c.key}><b>{c.title}</b>
            <span className="sub small">{c.kind === "cve" ? `${c.ranges?.length ?? 0} диапазонов версий в базе` : c.condition ?? ""}{c.ports.length ? ` · предполагаемые порты: ${c.ports.join(", ")}` : ""}{c.checks.length ? ` · специализированная проверка: ${c.checks.map((x) => x.id).join(", ")}` : ""}</span>
            {c.warnings.map((w) => <span key={w} className="sub small warn-text"><Icon name="alert" size={13} /> {w}</span>)}</li>))}</ul></section>}

      <section className="card"><h2>Где искать</h2>
        <div className="row"><span className="muted small">Режим:</span><Segmented<"ksc" | "network" | "combined"> label="Режим поиска" value={mode} onChange={setMode} options={[["combined", "Комбинированный", "Данные KSC и сетевая проверка"], ["network", "Сетевая проверка", "Активный поиск по выбранным адресам"], ["ksc", "По данным KSC", "Без сетевого сканирования"]]} /></div>
        <p className="muted small">{mode === "combined" ? "Рекомендуется: известные установки из KSC сопоставляются с результатами сетевой проверки, различия показываются." : mode === "network" ? "Активная проверка выбранных TCP-портов; инвентаризация KSC не используется." : "Только имеющиеся сведения KSC о программах: быстро, но данные могут быть неполными или устаревшими."}</p>
        <div className="cols mt">
          <label>Область<select value={scope.kind} onChange={(e) => setScope({ ...scope, kind: e.target.value as HuntScopeIn["kind"] })}>
            <option value="sources">Источники KSC (активные компьютеры)</option><option value="all">Вся инфраструктура (сети администратора и KSC)</option><option value="zones">Зоны ответственности</option><option value="groups">Группы компьютеров</option><option value="custom">Свои адреса и сети</option></select></label>
          {(scope.kind === "sources" || scope.kind === "all") && <MultiCheck label="Источники KSC" options={opts.sources} value={scope.sources} onChange={(v) => setScope({ ...scope, sources: v })} />}
          {scope.kind === "zones" && <MultiCheck label="Зоны" options={opts.zones} value={scope.zones} onChange={(v) => setScope({ ...scope, zones: v, sources: scope.sources.length ? scope.sources : opts.sources.map((s) => s.id) })} />}
          {scope.kind === "groups" && <label>Группа содержит<input value={scope.group} onChange={(e) => setScope({ ...scope, group: e.target.value, sources: scope.sources.length ? scope.sources : opts.sources.map((s) => s.id) })} placeholder="Серверы" /></label>}
          {scope.kind !== "custom" && <label>Активные за, суток<input type="number" min={1} max={3650} value={scope.active_days ?? 30} onChange={(e) => setScope({ ...scope, active_days: Number(e.target.value) })} /></label>}
        </div>
        {(scope.kind === "custom" || scope.kind === "all") && <label className="field mt">{scope.kind === "all" ? "Дополнительные адреса и сети" : "Адреса, сети и диапазоны"}<textarea rows={3} value={scope.text} onChange={(e) => setScope({ ...scope, text: e.target.value })} placeholder="192.0.2.10, 192.0.2.0/24, 192.0.2.20-30" /></label>}
        {scope.kind === "all" && opts.hunt_networks !== null && <p className="muted small">Сети администратора для целевого поиска: {opts.hunt_networks.length ? opts.hunt_networks.join(", ") : "не заданы (Администрирование → Pentest)"}.</p>}
        <label className="field mt">Исключить хосты и сети<input value={scope.exclude} onChange={(e) => setScope({ ...scope, exclude: e.target.value })} placeholder="192.0.2.5, 198.51.100.0/24" /></label>
      </section>

      {net && <section className="card"><h2>TCP-порты</h2>
        <p className="muted small">Проверяются только эти порты (не весь список портов и не полный Pentest). Порты подобраны по продуктам и прежним сканированиям; продукт может работать и на других портах.</p>
        <div className="chips">{(pv?.ports ?? crits.flatMap((c) => c.ports)).map((p) => <span key={p} className="chip-x mono">{p}</span>)}</div>
        <label className="field mt">Добавить порты и диапазоны<input value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="8081, 9000-9010" /></label></section>}

      <section className="card"><h2>Запуск</h2>
        {pv ? <p className="hunt-sum"><Icon name="info" size={15} /> {pv.text}{pv.excluded ? `; исключено компьютеров: ${pv.excluded}` : ""}.</p> : <p className="muted small">Сводка появится после выбора критериев и области.</p>}
        {pv?.rejected.length ? <ul className="pt-rej">{pv.rejected.slice(0, 5).map((r, i) => <li key={i}><span className="mono">{r.input}</span> — {r.reason}</li>)}</ul> : null}
        {noPorts && <div className="alert warn"><Icon name="alert" /><div className="alert-body">Для сетевой проверки нужен хотя бы один порт: добавьте его вручную.</div></div>}
        <label className="field">Название задания<input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} placeholder={cves[0] ? `Поиск ${cves[0]}` : "Целевой поиск"} /></label>
        {mode !== "ksc" && <label className="check"><input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />Подтверждаю, что проверка этих адресов разрешена</label>}
        {large && mode !== "ksc" && <label className="check"><input type="checkbox" checked={big} onChange={(e) => setBig(e.target.checked)} />Подтверждаю запуск на большом числе адресов ({num(pv!.targets)})</label>}
        <div className="form-actions"><button className="btn primary" disabled={busy || !crits.length || (!confirm && mode !== "ksc") || (large && !big && mode !== "ksc") || !!noPorts || !pv?.targets && mode !== "ksc"} onClick={() => void run()} aria-busy={busy}>
          <Icon name="target" size={16} /><span>{mode === "ksc" ? "Найти по данным KSC" : "Просканировать инфраструктуру"}</span></button></div>
      </section>
    </div>
  );
}

