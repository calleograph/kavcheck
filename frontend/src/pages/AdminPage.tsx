import { useSearchParams } from "react-router-dom";
import { ADMIN_TABS, type Ctx } from "../App";
import SourcesAdmin from "./admin/SourcesAdmin";
import UsersAdmin from "./admin/UsersAdmin";
import LdapAdmin from "./admin/LdapAdmin";
import GeneralAdmin from "./admin/GeneralAdmin";
import RulesAdmin from "./admin/RulesAdmin";
import UpdatesAdmin from "./admin/UpdatesAdmin";
import { AuditAdmin, JournalAdmin } from "./admin/JournalAdmin";
import SystemAdmin from "./admin/SystemAdmin";

export default function AdminPage({ ctx, version }: { ctx: Ctx; version: string }) {
  const [sp, setSp] = useSearchParams();
  const tab = ADMIN_TABS.some((t) => t.id === sp.get("tab")) ? sp.get("tab")! : "system";
  const go = (id: string) => setSp({ tab: id });
  return (
    <section>
      <div className="row"><h1>Администрирование</h1><div className="spacer" /><span className="muted small">Версия: {version || "—"}</span></div>
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
