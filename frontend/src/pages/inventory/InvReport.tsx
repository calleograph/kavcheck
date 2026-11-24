/** Отчёты инвентаризации со страницы: выбор вида отчёта → общий конструктор (QuickReportPanel, вид quick_inv) с отбором и выбранными строками страницы. */
import { useState } from "react";
import { Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { QuickReportPanel } from "../../components/QuickReport";
import { useInv } from "./InvBits";

export interface ReportView { view: string; title: string; hint: string; group: string }
export const REPORT_VIEWS: ReportView[] = [
  { view: "registry", title: "Реестр ИТ-оборудования", hint: "все учётные поля, сводки по типам, местоположениям и статусам", group: "Реестры" },
  { view: "computers", title: "Реестр компьютеров и серверов", hint: "имя компьютера, ответственные, связь с KSC", group: "Реестры" },
  { view: "components", title: "Комплектующие и состав", hint: "что во что входит", group: "Реестры" },
  { view: "duplicates", title: "Возможные дубли карточек", hint: "совпадение серийного номера или имени", group: "Реестры" },
  { view: "by_person", title: "Оборудование по сотрудникам", hint: "за кем что закреплено (пользователь)", group: "Принадлежность" },
  { view: "by_resp", title: "Оборудование по ответственным", hint: "ответственные за оборудование", group: "Принадлежность" },
  { view: "owner_history", title: "История принадлежности", hint: "смена пользователей, владельцев, ответственных за период", group: "Принадлежность" },
  { view: "by_location", title: "По регионам и помещениям", hint: "состав по местоположениям", group: "Расположение" },
  { view: "geography", title: "Сетевые местоположения", hint: "площадки, статус, источник и актуальность сетевых наблюдений", group: "Расположение" },
  { view: "moves", title: "История перемещений", hint: "смена местоположения за период", group: "Расположение" },
  { view: "stock", title: "Оборудование на складе", hint: "на складе и в резерве", group: "Состояние" },
  { view: "repair", title: "Оборудование в ремонте", hint: "и открытые ремонты", group: "Состояние" },
  { view: "warranty", title: "Истекающая гарантия", hint: "по сроку из настроек", group: "Состояние" },
  { view: "writtenoff", title: "Списанное оборудование", hint: "списано, выведено, утрачено", group: "Состояние" },
  { view: "cost", title: "Стоимость оборудования", hint: "по типам, местоположениям, подразделениям", group: "Состояние" },
  { view: "hardware", title: "Аппаратная конфигурация", hint: "процессоры и память по данным KSC", group: "Технические (KSC)" },
  { view: "software", title: "Реестр установленного ПО", hint: "программы на связанных компьютерах", group: "Технические (KSC)" },
  { view: "licenses", title: "Реестр лицензий", hint: "купленные лицензии, сроки, поставщики", group: "Лицензии" },
  { view: "license_usage", title: "Использование лицензий", hint: "куплено, назначено, установлено, расхождения", group: "Лицензии" },
  { view: "count", title: "Результаты инвентаризации", hint: "все строки, расхождения, по помещениям (по умолчанию — последняя)", group: "Инвентаризация" },
  { view: "count_diff", title: "Расхождения инвентаризации", hint: "не найдено, в другом месте, лишнее, нет в учёте", group: "Инвентаризация" },
  { view: "infra_registry", title: "Реестр серверной инфраструктуры", hint: "физические серверы, ВМ, сеть — поля по приоритету источников", group: "Инфраструктура" },
  { view: "infra_hypervisors", title: "Гипервизоры и кластеры", hint: "хосты виртуализации, число ВМ", group: "Инфраструктура" },
  { view: "infra_ips", title: "IP-адреса, подсети и VLAN", hint: "владельцы адресов и повторы", group: "Инфраструктура" },
  { view: "infra_racks", title: "Оборудование по стойкам", hint: "занятые и свободные юниты", group: "Инфраструктура" },
  { view: "infra_findings", title: "Расхождения между источниками", hint: "мониторинг, резервное копирование, учёт, сеть", group: "Инфраструктура" },
  { view: "infra_changes", title: "Изменения конфигурации", hint: "CPU, память, адреса, хост — за период", group: "Инфраструктура" },
  { view: "infra_new_gone", title: "Новые и исчезнувшие объекты", hint: "за период", group: "Инфраструктура" },
  { view: "infra_sync", title: "Синхронизация источников", hint: "последняя успешная, ошибки, объём", group: "Инфраструктура" },
  { view: "infra_decom", title: "Вывод из эксплуатации", hint: "документы и незавершённые действия", group: "Инфраструктура" },
  { view: "infra_asof", title: "Состояние инфраструктуры на дату", hint: "статус, размещение, ответственный", group: "Инфраструктура" },
  { view: "infra_netscan", title: "Сетевое обнаружение", hint: "найденные узлы, тип, ОС, порты, есть ли карточка", group: "Инфраструктура" },
  { view: "infra_review", title: "Периодическая проверка", hint: "полнота реестра, ответственные, мониторинг, копии (дважды в год)", group: "Инфраструктура" },
  { view: "docs", title: "Журнал документов", hint: "выдачи, возвраты, перемещения, ремонты", group: "Документы" },
];

export function useInvReport() {
  const [pick, setPick] = useState<{ params: Record<string, unknown>; views: string[]; label: string } | null>(null);
  const [run, setRun] = useState<{ view: ReportView; params: Record<string, unknown> } | null>(null);
  const open = (views: string[], params: Record<string, unknown>, label = "") => {
    if (views.length === 1) { const v = REPORT_VIEWS.find((x) => x.view === views[0])!; setRun({ view: v, params: { ...params, view: v.view } }); }
    else setPick({ views, params, label });
  };
  const node = <ReportNodes pick={pick} run={run} onPick={(v) => { setRun({ view: v, params: { ...pick!.params, view: v.view } }); setPick(null); }} onClose={() => { setPick(null); setRun(null); }} />;
  return { open, node };
}

function ReportNodes({ pick, run, onPick, onClose }: { pick: { params: Record<string, unknown>; views: string[]; label: string } | null; run: { view: ReportView; params: Record<string, unknown> } | null;
  onPick: (v: ReportView) => void; onClose: () => void }) {
  const { activityDays, role } = useInv();
  const can = role !== "viewer";
  if (run) return <QuickReportPanel kind="quick_inv" title={run.view.title} lede={run.view.hint} params={run.params} options={{ scope: false }} activityDays={activityDays} canReport={can} onClose={onClose} />;
  if (!pick) return null;
  const views = REPORT_VIEWS.filter((v) => pick.views.includes(v.view));
  const groups = [...new Set(views.map((v) => v.group))];
  return (
    <Modal title="Сформировать отчёт" lede={pick.label || "Отчёт по текущей выборке страницы"} onClose={onClose}>
      <div className="inv-rpick">{groups.map((g) => <div key={g}><h3 className="vdb-h">{g}</h3><ul>{views.filter((v) => v.group === g).map((v) => (
        <li key={v.view}><button type="button" className="inv-rpick-b" onClick={() => onPick(v)}><Icon name="file" size={16} /><span><b>{v.title}</b><span className="sub muted">{v.hint}</span></span></button></li>))}</ul></div>)}</div>
    </Modal>
  );
}
