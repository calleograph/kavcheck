import { useSearchParams } from "react-router-dom";
import { ADMIN_TABS, type Ctx } from "../App";
import { PageHead } from "../components/ui";
import SourcesAdmin from "./admin/SourcesAdmin";
import UsersAdmin from "./admin/UsersAdmin";
import LdapAdmin from "./admin/LdapAdmin";
import GeneralAdmin from "./admin/GeneralAdmin";
import RulesAdmin from "./admin/RulesAdmin";
import UpdatesAdmin from "./admin/UpdatesAdmin";
import { AuditAdmin, JournalAdmin } from "./admin/JournalAdmin";
import SystemAdmin from "./admin/SystemAdmin";

const LEDE: Record<string, string> = {
  system: "Работают ли сервисы KAV Checker и доступны ли источники KSC.",
  sources: "Подключения к базам Серверов администрирования KSC. Только чтение: используйте учётную запись с ролью db_datareader.",
  users: "Учётные записи, роли и доступ к источникам KSC.",
  ldap: "Вход по учётным записям каталога и роли по группам.",
  general: "Порог активности компьютеров, сроки хранения и ограничения отчётов.",
  rules: "Как пакеты объединяются в продукты и по каким признакам определяется ветка версии.",
  updates: "Версия KAV Checker, релизы GitHub, обновление, откат и резервные копии.",
  journal: "Входы, проверки и запросы к источникам, формирование отчётов, ошибки.",
  audit: "Кто, что и когда сделал в KAV Checker.",
};

export default function AdminPage({ ctx }: { ctx: Ctx; version: string }) {
  const [sp, setSp] = useSearchParams();
  const tab = ADMIN_TABS.some((t) => t.id === sp.get("tab")) ? sp.get("tab")! : "system";
  const go = (id: string) => setSp({ tab: id });
  const label = ADMIN_TABS.find((t) => t.id === tab)!.label;
  return (
    <section>
      <PageHead title={label} lede={LEDE[tab]} />
      {tab === "system" && <SystemAdmin onOpen={go} />}
      {tab === "sources" && <SourcesAdmin ctx={ctx} />}
      {tab === "users" && <UsersAdmin ctx={ctx} />}
      {tab === "ldap" && <LdapAdmin />}
      {tab === "general" && <GeneralAdmin />}
      {tab === "rules" && <RulesAdmin />}
      {tab === "updates" && <UpdatesAdmin />}
      {tab === "journal" && <JournalAdmin />}
      {tab === "audit" && <AuditAdmin />}
    </section>
  );
}
