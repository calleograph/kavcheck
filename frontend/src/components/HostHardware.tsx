import { useEffect, useState } from "react";
import { api, type ApiError, type HostHardware, type HwDisk } from "../api";
import { Icon } from "./Icons";
import { Empty, SkelRows } from "./ui";
import { fmt, num } from "../util";

const ND = <span className="muted">Нет данных</span>;
const gb = (v: number | null | undefined) => (v ? `${v.toLocaleString("ru-RU")} ГБ` : ND);
const ram = (mb: number | null | undefined) => (mb ? (mb >= 1024 ? `${(mb / 1024).toLocaleString("ru-RU", { maximumFractionDigits: 1 })} ГБ` : `${mb} МБ`) : ND);

/** Загрузка сведений об оборудовании для карточки (одна выборка из KSC: вкладка и компактная строка «Сведения» используют один результат). */
export function useHardware(hostId: number, enabled: boolean) {
  const [d, setD] = useState<HostHardware | null>(null); const [err, setErr] = useState("");
  useEffect(() => { setD(null); setErr(""); if (enabled) api.hosts.hardware(hostId).then(setD).catch((e) => setErr((e as ApiError).message)); }, [hostId, enabled]);
  return { d, err };
}

/** Проблемы ресурсов Linux-сервера с фактическими значениями и порогами. */
export function HwProblems({ d }: { d: HostHardware }) {
  if (!d.problems.length) return null;
  return <>{d.problems.map((p) => <div key={p.key} className={`alert flat ${p.level === "critical" ? "error" : "warn"}`}><Icon name="alert" /><div className="alert-body"><b>{p.title}</b> ({p.level_ru.toLowerCase()}): {p.text}.</div></div>)}</>;
}

function Disks({ title, items, note }: { title: string; items: HwDisk[]; note?: string }) {
  if (!items.length) return null;
  return (
    <div className="card flush"><div className="card-head"><h2>{title}</h2>{note && <span className="muted small">{note}</span>}</div>
      <div className="table-scroll"><table className="table compact"><thead><tr><th>Название</th><th className="num">Объём</th><th className="num">Свободно</th><th className="hide-sm">Серийный номер</th></tr></thead>
        <tbody>{items.map((x, i) => <tr key={i}><td>{x.name || "—"}{x.manuf && <span className="sub small">{x.manuf}</span>}</td><td className="num">{gb(x.total_gb)}</td><td className="num">{gb(x.free_gb)}</td><td className="mono small hide-sm">{x.serial || "—"}</td></tr>)}</tbody></table></div></div>
  );
}

/** Вкладка «Аппаратная часть»: процессоры, ОЗУ, накопители (физические отдельно от разделов и томов), сеть, плата. */
export function HardwareTab({ d, err }: { d: HostHardware | null; err: string }) {
  if (err) return <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>;
  if (!d) return <div className="card"><SkelRows rows={4} cols={3} /></div>;
  const h = d.hw;
  if (!d.supported || !h.known) return <Empty icon="monitor" title="Нет данных об оборудовании">{d.supported ? "Агент администрирования не передавал инвентаризацию оборудования этого компьютера." : "В базе источника нет таблиц инвентаризации оборудования KSC."} Оценка достаточности ресурсов не выполняется.</Empty>;
  return (
    <div className="stack">
      <HwProblems d={d} />
      {d.linux && !d.problems.length && h.cores != null && h.ram_mb != null && <p className="muted small">Ресурсы Linux-сервера в норме: ядер — {h.cores} (норма от {d.thresholds.cpu_ok_cores}), ОЗУ — {ram(h.ram_mb)} (порог {ram(d.thresholds.ram_min_mb)}).</p>}
      {d.linux && (h.cores == null || h.ram_mb == null) && <p className="muted small">Часть показателей KSC не передал — по ним оценка достаточности ресурсов не выполняется.</p>}
      {h.virtual && <p className="muted small">Виртуальная машина: показаны ресурсы, выделенные гипервизором.</p>}
      <div className="card"><h2>Сводка</h2>
        <dl className="kv pairs">
          <div><dt>Процессоры</dt><dd>{h.sockets ?? ND}{h.cpus?.[0]?.name && <span className="sub small">{h.cpus[0].name}{h.cpus[0].mhz ? `, ${num(h.cpus[0].mhz)} МГц` : ""}</span>}</dd></div>
          <div><dt>Ядра / потоки</dt><dd>{h.cores != null ? `${h.cores}${h.threads ? ` / ${h.threads}` : ""}` : ND}</dd></div>
          <div><dt>Оперативная память</dt><dd>{ram(h.ram_mb)}{h.ram_modules && h.ram_modules.length > 0 && <span className="sub small">модулей: {h.ram_modules.length}</span>}</dd></div>
          <div><dt>Диски (физические)</dt><dd>{gb(h.disk_total_gb)}{h.disk_free_gb != null && <span className="sub small">свободно {gb(h.disk_free_gb)}</span>}{h.disks_logical_only && <span className="sub small">физические диски не переданы: показан наибольший логический том</span>}</dd></div>
          {h.board && <div><dt>Плата и BIOS</dt><dd>{[h.board.manuf, h.board.board].filter(Boolean).join(" ") || "—"}<span className="sub small">BIOS {h.board.bios_manuf} {h.board.bios_version}{h.board.bios_date ? `, ${fmt(h.board.bios_date)}` : ""}</span></dd></div>}
        </dl></div>
      <Disks title="Накопители" items={h.disks ?? []} />
      <Disks title="Логические тома и разделы" items={h.logical ?? []} note="в итог по дискам не входят — иначе объём считался бы дважды" />
      {(h.nics?.length ?? 0) > 0 && <div className="card flush"><div className="card-head"><h2>Сетевые адаптеры</h2></div><div className="table-scroll"><table className="table compact"><thead><tr><th>Адаптер</th><th>MAC-адрес</th><th className="num">Скорость</th></tr></thead>
        <tbody>{h.nics!.map((n, i) => <tr key={i}><td>{n.name}</td><td className="mono small">{n.mac || "—"}</td><td className="num">{n.speed_mbit ? `${num(n.speed_mbit)} Мбит/с` : "—"}</td></tr>)}</tbody></table></div></div>}
      {(h.other?.length ?? 0) > 0 && <p className="muted small">Также: {h.other!.map((o) => `${o.type}: ${o.name}`).join("; ")}.</p>}
      {d.fetched_at && <p className="muted small">Данные инвентаризации из KSC получены {fmt(d.fetched_at)}.</p>}
    </div>
  );
}
