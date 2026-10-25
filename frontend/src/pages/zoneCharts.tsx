import type { HostState, ProblemKey, ZoneStats } from "../api";
import { Donut, HBars, type Seg } from "../components/Charts";
import { num } from "../util";

type Pick = (k: "state" | "severity" | "problem", v: string) => void;

/** Три компактные диаграммы зоны: состояние компьютеров (кольцо), критичность, категории проблем. Щелчок по сегменту отбирает компьютеры в таблице ниже. */
export function Charts({ st, f, pick, ext }: { st: ZoneStats; f: Record<string, string>; pick: Pick; ext: boolean }) {
  const states: Seg[] = ([["critical", "Критические уязвимости"], ["vulns", "Другие уязвимости"], ["protection", "Только проблемы защиты"], ["potential", "Только потенциальные"], ["ok", "Без проблем"]] as [HostState, string][])
    .filter(([k]) => ext || k !== "potential").map(([k, l]) => ({ key: k, label: l, value: st.state[k] ?? 0, tone: k, hint: k === "potential" ? "Есть только совпадения по внешним базам, KSC уязвимостей не подтвердил" : undefined }));
  const sev: Seg[] = [{ key: "critical", label: "Критическая", value: st.severity.critical, tone: "critical" }, { key: "high", label: "Высокая", value: st.severity.high, tone: "high" },
    { key: "warning", label: "Предупреждение", value: st.severity.warning, tone: "warning" }, { key: "none", label: "Без уязвимостей", value: st.severity.none, tone: "ok" }];
  const probs: Seg[] = st.problems.map((p) => ({ key: p.key as ProblemKey, label: p.title, value: p.hosts, tone: "protection" }));
  return (
    <div className="charts">
      <div className="card chart-card"><h3>Состояние компьютеров</h3>
        <Donut label="Распределение компьютеров по состоянию" segs={states} selected={f.state} onSelect={(k) => pick("state", k)} center={{ value: num(st.active), label: "активных" }} />
        <p className="muted xs">По наиболее серьёзной проблеме: сумма равна числу активных компьютеров.</p></div>
      <div className="card chart-card"><h3>Максимальная критичность</h3>
        <HBars label="Компьютеры по максимальной критичности" rows={sev} selected={f.severity} onSelect={(k) => pick("severity", k)} />
        <p className="muted xs">Обнаружений: критических {num(st.vulns.critical)}, высоких {num(st.vulns.high)}, предупреждений {num(st.vulns.warning)}.</p></div>
      <div className="card chart-card"><h3>Проблемы защиты</h3>
        <HBars label="Компьютеры по категориям проблем защиты" rows={probs} selected={f.problem} onSelect={(k) => pick("problem", k)} />
        <p className="muted xs">Один компьютер может быть в нескольких строках.</p></div>
    </div>
  );
}
