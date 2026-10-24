import { useSearchParams } from "react-router-dom";
import { ADMIN_TABS, type Ctx } from "../App";
import { PageHead } from "../components/ui";
import SourcesAdmin from "./admin/SourcesAdmin";
import UsersAdmin from "./admin/UsersAdmin";
import LdapAdmin from "./admin/LdapAdmin";
import GeneralAdmin from "./admin/GeneralAdmin";
import CatalogAdmin from "./admin/CatalogAdmin";
import VdbAdmin from "./admin/VdbAdmin";
import UpdatesAdmin from "./admin/UpdatesAdmin";
import { AuditAdmin, JournalAdmin } from "./admin/JournalAdmin";
import SystemAdmin from "./admin/SystemAdmin";

const LEDE: Record<string, string> = {
  system: "Работают ли сервисы KAV Checker и доступны ли источники KSC.",
  sources: "Подключения к базам Серверов администрирования KSC. Только чтение: используйте учётную запись с ролью db_datareader.",
  users: "Учётные записи, роли и доступ к источникам KSC.",
  ldap: "Вход доменных пользователей: подключения LDAPS, доверенные сертификаты, правила доступа по группам Active Directory.",
  general: "Какие компьютеры показывать в рабочих разделах, сроки хранения и ограничения отчётов.",
  catalog: "Как записи реестра KSC объединяются в продукты и ветки: состояние каталога, ручные исправления, правила для опытных.",
  vdb: "Источники сведений об уязвимостях (NVD, CISA KEV, OSV, БДУ ФСТЭК): включение, расписание обновления, состояние загрузок и решения по сопоставлению продуктов.",
  updates: "Версия KAV Checker, релизы GitHub, обновление, откат и резервные копии.",
  journal: "Входы, проверки и запросы к источникам, формирование отчётов, ошибки.",
  audit: "Кто, что и когда сделал в KAV Checker.",
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
      {tab === "users" && <UsersAdmin ctx={ctx} />}
      {tab === "ldap" && <LdapAdmin sources={ctx.sources} />}
      {tab === "general" && <GeneralAdmin />}
      {tab === "catalog" && <CatalogAdmin />}
      {tab === "vdb" && <VdbAdmin />}
      {tab === "updates" && <UpdatesAdmin />}
      {tab === "journal" && <JournalAdmin />}
      {tab === "audit" && <AuditAdmin />}
    </section>
  );
}
