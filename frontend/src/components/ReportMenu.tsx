import { useState } from "react";
import type { QuickKind } from "../api";
import { Modal } from "./Dialogs";
import { ReportButton } from "./FilterBar";
import { Icon, type IconName } from "./Icons";
import { QuickReportPanel, type QuickScopeOpts } from "./QuickReport";

interface Entry { kind: QuickKind; icon: IconName; title: string; sub: string; params: Record<string, unknown>; options: QuickScopeOpts }

const ENTRIES: Entry[] = [
  { kind: "quick_protection", icon: "shieldPulse", title: "Состояние защиты", sub: "Все компьютеры источника: продукты Kaspersky, базы, проверки, проблемы", params: {}, options: { scope: true, zoneFilter: true } },
  { kind: "quick_vulns", icon: "bug", title: "Уязвимости, найденные KSC", sub: "Все действующие обнаружения: компьютеры, программы, CVE", params: {}, options: { scope: true, severity: true, patchable: true } },
  { kind: "quick_eol", icon: "clock", title: "EOL: ПО и ОС без поддержки", sub: "Программы и операционные системы с закончившейся поддержкой и устройства", params: {}, options: { scope: false, eol: true, zoneFilter: true } },
  { kind: "quick_devices", icon: "monitor", title: "Устройства и пользователи", sub: "Устройства с зонами, пользователями и признаком EOL", params: {}, options: { scope: false } },
  { kind: "quick_hosts", icon: "monitor", title: "Компьютеры", sub: "Список компьютеров с защитой (ПО и уязвимости — по выбору, до 500 компьютеров)", params: {}, options: { sections: true, scope: false } },
];

/** «Сформировать отчёт» на страницах без таблицы с фильтрами (главная, обзоры): выбор вида отчёта, затем единый конструктор. */
export function ReportMenu({ activityDays, canReport, sourceIds = [] }: { activityDays: number; canReport: boolean; sourceIds?: string[] }) {
  const [open, setOpen] = useState(false); const [pick, setPick] = useState<Entry | null>(null);
  if (!canReport) return null;
  return (
    <>
      <ReportButton onClick={() => setOpen(true)} title="Выбрать вид отчёта и открыть конструктор" />
      {open && !pick && (
        <Modal title="Сформировать отчёт" lede="Выберите, что включить. Условия можно изменить в конструкторе: подробность, столбцы, фильтры, формат." onClose={() => setOpen(false)}>
          <nav aria-label="Виды отчётов">{ENTRIES.map((e) => (
            <button key={e.kind} type="button" className="action-row report-pick" onClick={() => setPick(e)}>
              <span className="a-ic"><Icon name={e.icon} /></span><span className="a-main"><b>{e.title}</b><span>{e.sub}</span></span><Icon name="chevronR" className="a-go" />
            </button>))}</nav>
        </Modal>)}
      {pick && <QuickReportPanel kind={pick.kind} title={pick.title} lede={pick.sub} options={pick.options} params={pick.params} sourceIds={sourceIds} activityDays={activityDays} canReport={canReport} onClose={() => { setPick(null); setOpen(false); }} />}
    </>
  );
}
