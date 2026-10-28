import { useSearchParams } from "react-router-dom";
import { ADMIN_TABS, type Ctx } from "../App";
import { PageHead } from "../components/ui";
import SourcesAdmin from "./admin/SourcesAdmin";
import LicensesAdmin from "./admin/LicensesAdmin";
import PentestAdmin from "./admin/PentestAdmin";
import ChecksAdmin from "./admin/ChecksAdmin";
import UsersAdmin from "./admin/UsersAdmin";
import LdapAdmin from "./admin/LdapAdmin";
import GeneralAdmin from "./admin/GeneralAdmin";
import CatalogAdmin from "./admin/CatalogAdmin";
import VdbAdmin from "./admin/VdbAdmin";
import UpdatesAdmin from "./admin/UpdatesAdmin";
import { AuditAdmin, JournalAdmin } from "./admin/JournalAdmin";
import SystemAdmin from "./admin/SystemAdmin";
import ZonesAdmin from "./admin/ZonesAdmin";
import MailAdmin from "./admin/MailAdmin";
import OrgAdmin from "./admin/OrgAdmin";
import CacheAdmin from "./admin/CacheAdmin";
import EolAdmin from "./admin/EolAdmin";
import LogsAdmin from "./admin/LogsAdmin";
import ComponentsAdmin from "./admin/ComponentsAdmin";

const LEDE: Record<string, string> = {
  system: "Работают ли сервисы KAV Checker и доступны ли источники KSC.",
  sources: "Подключения к базам Серверов администрирования KSC. Только чтение: используйте учётную запись с ролью db_datareader.",
  users: "Учётные записи, роли и доступ к источникам KSC.",
  ldap: "Вход доменных пользователей: подключения LDAPS, доверенные сертификаты, правила доступа по группам Active Directory.",
  general: "Какие компьютеры показывать в рабочих разделах, сроки хранения и ограничения отчётов.",
  zones: "Группы компьютеров по сетям и группам KSC с ответственными: создание, импорт из CSV, спорные компьютеры. Анализ зон — в разделе «Зоны ответственности».",
  zcache: "Ночной расчёт данных зон: расписание, ограничения ресурсов, состояние по источникам KSC, очередь заданий.",
  eolcfg: "Окончание поддержки ПО и ОС (EOL): что считать проблемой; опрос пользователей устройств: интервал, хранение, служебные учётные записи; пороги ядер CPU и ОЗУ для Linux-серверов.",
  mail: "Автоматическая отправка отчётов ответственным: расписания, история отправок, подключение к серверу почты.",
  org: "Название организации, подразделение, логотип и примечания для шапок и подвалов отчётов.",
  catalog: "Как записи реестра KSC объединяются в продукты и ветки: состояние каталога, ручные исправления, правила для опытных.",
  vdb: "Источники сведений об уязвимостях (NVD, CISA KEV, OSV, БДУ ФСТЭК): включение, расписание обновления, состояние загрузок и решения по сопоставлению продуктов.",
  ptchecks: "Pentest: движок Nuclei и шаблоны (версия, контрольная сумма, обновление), каталог проверок Nmap NSE и Nuclei с политикой безопасности и решениями администратора.",
  updates: "Версия KAV Checker, релизы GitHub, обновление, откат и резервные копии.",
  journal: "Входы, проверки и запросы к источникам, формирование отчётов, ошибки.",
  audit: "Кто, что и когда сделал в KAV Checker.",
  components: "Что установлено в KAV Checker, какие версии доступны у разработчиков и какие решения приняты по обновлению. Обновление приложения — только проверенным выпуском.",
  logs: "Сроки, объём, архивы и квота всех журналов: событий приложения, действий, выполнения заданий Pentest. Результаты сканирований этими настройками не затрагиваются.",
};

export default function AdminPage({ ctx }: { ctx: Ctx; version: string }) {
  const [sp, setSp] = useSearchParams();
  const raw = sp.get("tab") === "rules" ? "catalog" : sp.get("tab");
  const tab = ADMIN_TABS.some((t) => t.id === raw) ? raw! : "system";
  const go = (id: string) => setSp({ tab: id });
  const label = ADMIN_TABS.find((t) => t.id === tab)!.label;
  return (
    <section>
      <PageHead title={label} lede={LEDE[tab]} />
      {tab === "system" && <SystemAdmin onOpen={go} />}
      {tab === "sources" && <SourcesAdmin ctx={ctx} />}
      {tab === "licenses" && <LicensesAdmin sources={ctx.sources} />}
      {tab === "pentest" && <PentestAdmin />}
      {tab === "ptchecks" && <ChecksAdmin />}
      {tab === "users" && <UsersAdmin ctx={ctx} />}
      {tab === "ldap" && <LdapAdmin sources={ctx.sources} />}
      {tab === "general" && <GeneralAdmin />}
      {tab === "zones" && <ZonesAdmin />}
      {tab === "zcache" && <CacheAdmin />}
      {tab === "eolcfg" && <EolAdmin />}
      {tab === "logs" && <LogsAdmin />}
      {tab === "components" && <ComponentsAdmin />}
      {tab === "mail" && <MailAdmin sources={ctx.sources} />}
      {tab === "org" && <OrgAdmin />}
      {tab === "catalog" && <CatalogAdmin />}
      {tab === "vdb" && <VdbAdmin />}
      {tab === "updates" && <UpdatesAdmin />}
      {tab === "journal" && <JournalAdmin />}
      {tab === "audit" && <AuditAdmin />}
    </section>
  );
}
