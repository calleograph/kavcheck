import { useEffect, useState } from "react";
import { req } from "../../api";
import { DB_IP_LITE, GEOLITE, GeoIpAttribution } from "../../components/DbIpAttribution";
import { Icon } from "../../components/Icons";
import { AdminReportButton } from "../../components/QuickReport";
import { SkelRows } from "../../components/ui";
import { fmt, fmtDate } from "../../util";

const PROVIDERS = {
  mirror: { name: "GeoLite2 (зеркало)", databases: ["GeoLite2-City", "GeoLite2-ASN", "GeoLite2-Country"] },
  dbip: { name: DB_IP_LITE, databases: ["DBIP-City-Lite", "DBIP-ASN-Lite"] },
  maxmind: { name: "GeoLite2 (MaxMind)", databases: ["GeoLite2-City", "GeoLite2-ASN"] },
};
type Provider = keyof typeof PROVIDERS;
interface Status {
  provider: Provider; active_provider: Provider | null;
  enabled: boolean; account_id: string; license_key_set: boolean;
  mirror_url: string; mirror_expired: boolean;
  running: boolean; pending: boolean; stage: string; checked_at: string | null; success_at: string | null;
  next_check_at: string | null; error: string;
  databases: Record<string, { build_epoch: number; last_modified: string }>;
}
const PATH = "/inv/geography/geoip";

export default function InvGeoSettings() {
  const [status, setStatus] = useState<Status | null>(null);
  const [provider, setProvider] = useState<Provider>("mirror");
  const [mirrorUrl, setMirrorUrl] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [account, setAccount] = useState("");
  const [key, setKey] = useState("");
  const [clear, setClear] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [retry, setRetry] = useState(0);

  useEffect(() => {
    let active = true;
    req<Status>("GET", PATH).then((s) => {
      if (active) { setStatus(s); setProvider(s.provider); setMirrorUrl(s.mirror_url); setAccount(s.account_id); setEnabled(s.enabled); setError(""); }
    }).catch((e: Error) => { if (active) setError(e.message); });
    return () => { active = false; };
  }, [retry]);

  const checking = Boolean(status?.running || status?.pending);
  useEffect(() => {
    if (!checking) return;
    let active = true;
    const timer = window.setInterval(() => {
      req<Status>("GET", PATH).then((s) => { if (active) setStatus(s); }).catch(() => undefined);
    }, 3000);
    return () => { active = false; window.clearInterval(timer); };
  }, [checking]);

  const maxmind = provider === "maxmind";
  const mirror = provider === "mirror";
  const dirty = status && (status.provider !== provider || status.enabled !== enabled ||
    (mirror && status.mirror_url !== mirrorUrl.trim()) ||
    (maxmind && (status.account_id !== account.trim() || Boolean(key.trim()) || clear)));
  const save = async () => {
    setBusy(true); setError(""); setNotice("");
    try {
      await req("PUT", "/admin/settings/geoip", { provider, enabled, ...(mirror ? { mirror_url: mirrorUrl.trim() } : {}),
        ...(maxmind ? { account_id: account.trim(),
        ...(clear ? { license_key: "" } : key.trim() ? { license_key: key.trim() } : {}) } : {}) });
      setKey(""); setClear(false);
      const current = await req<Status>("GET", PATH);
      setStatus(current); setAccount(current.account_id); setMirrorUrl(current.mirror_url);
      setNotice("Настройки сохранены.");
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  };
  const refresh = async () => {
    setBusy(true); setError(""); setNotice("");
    try { setStatus(await req<Status>("POST", `${PATH}/refresh`)); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  };

  if (!status) return <div className="card">{error ? <>
    <p className="field-err" role="alert">{error}</p>
    <button className="btn" onClick={() => setRetry((n) => n + 1)}>Повторить</button>
  </> : <SkelRows rows={4} cols={2} />}</div>;

  const names = PROVIDERS[status.active_provider ?? status.provider].databases;
  const credentialsReady = status.provider !== "maxmind" || Boolean(status.account_id && status.license_key_set);
  return <div className="split even">
    <form className="card form-stack" onSubmit={(e) => { e.preventDefault(); void save(); }}>
      <h2>Источник географических баз</h2>
      <label className="field">Поставщик<select value={provider} disabled={busy} onChange={(e) => {
        setProvider(e.target.value as Provider); setKey(""); setClear(false); setNotice("");
      }}>
        <option value="mirror">GeoLite2 (зеркало)</option><option value="maxmind">GeoLite2 (напрямую от MaxMind)</option>
        <option value="dbip">DB-IP Lite</option>
      </select></label>
      <p className="small muted">{maxmind ? "Для прямой загрузки нужны учётная запись и ключ MaxMind." :
        mirror ? "City, ASN и Country проверяются ежедневно. Для зеркала достаточно доступа к интернету." :
        "Бесплатные базы City и ASN обновляются ежемесячно."} Поиск по IP выполняется локально.</p>
      {mirror && <>
        <label className="field">Альтернативный HTTPS-каталог<input type="url" value={mirrorUrl} onChange={(e) => setMirrorUrl(e.target.value)}
          autoComplete="off" maxLength={2048} disabled={busy} aria-describedby="mirror-help" /></label>
        <p id="mirror-help" className="small muted">Оставьте поле пустым для загрузки из <a href="https://github.com/P3TERX/GeoLite.mmdb/releases" target="_blank" rel="noreferrer">зеркала P3TERX на GitHub</a>. Другой каталог должен содержать три MMDB-файла и SHA256SUMS.</p>
      </>}
      {maxmind && <>
        <label className="field">Номер учётной записи<input value={account} onChange={(e) => setAccount(e.target.value)}
          inputMode="numeric" autoComplete="off" pattern="[0-9]*" maxLength={18} disabled={busy} /></label>
        <label className="field">Лицензионный ключ<input type="password" value={key} onChange={(e) => setKey(e.target.value)}
          autoComplete="new-password" maxLength={128} disabled={busy || clear} placeholder={status.license_key_set ? "Сохранён" : ""} /></label>
      </>}
      <label className="check-row"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)}
        disabled={busy || clear} />Автоматически загружать и обновлять базы</label>
      {maxmind && status.license_key_set && <label className="check-row"><input type="checkbox" checked={clear} disabled={busy}
        onChange={(e) => { setClear(e.target.checked); if (e.target.checked) { setKey(""); setEnabled(false); } }} />Удалить ключ при сохранении</label>}
      <div className="row wrap">
        <button className="btn primary" type="submit" disabled={!dirty || busy}><Icon name="save" size={16} />Сохранить настройки</button>
        <button className="btn" type="button" disabled={!!dirty || busy || checking || !credentialsReady}
          onClick={() => void refresh()}><Icon name="refresh" size={16} />Проверить и загрузить сейчас</button>
      </div>
      {error && <p className="field-err" role="alert">{error}</p>}
      {notice && <p role="status">{notice}</p>}
    </form>
    <section className="card stack">
      <div className="card-head"><h2>Управляемые базы</h2><div className="spacer" />
        <AdminReportButton view="geoip" title="Географические базы" />
      </div>
      <p role="status">{status.running ? status.stage || "Проверка географических баз" : status.pending ? "Загрузка поставлена в очередь" :
        status.enabled ? "Автоматическая проверка включена" : "Автоматическая проверка выключена"}</p>
      {status.error && <p className="field-err" role="alert">{status.error}</p>}
      {status.mirror_expired && <p className="small muted">Срок использования комплекта из зеркала истёк. Ожидается свежий выпуск.</p>}
      <dl className="kv">
        <dt>Загруженный источник</dt><dd>{status.active_provider ? PROVIDERS[status.active_provider].name : "Ожидает первой загрузки"}</dd>
        <dt>Последняя проверка</dt><dd>{fmt(status.checked_at)}</dd>
        <dt>Последняя успешная проверка</dt><dd>{fmt(status.success_at)}</dd>
        {status.enabled && <><dt>Следующая проверка</dt><dd>{fmt(status.next_check_at)}</dd></>}
        {names.map((name) => <DatabaseDate key={name} name={name} build={status.databases[name]?.build_epoch} />)}
      </dl>
      <p className="small muted">При сетевой ошибке действует последний пригодный комплект. Для зеркала срок использования ограничен 30 днями от сборки. Ручные MMDB можно разместить в каталоге GeoIP установки и отключить автообновление.</p>
      {(provider === "dbip" || status.active_provider === "dbip") && <p className="small muted"><GeoIpAttribution provider={DB_IP_LITE} /></p>}
      {(provider !== "dbip" || (status.active_provider && status.active_provider !== "dbip")) &&
        <p className="small muted"><GeoIpAttribution provider={GEOLITE} /></p>}
    </section>
  </div>;
}

function DatabaseDate({ name, build }: { name: string; build?: number }) {
  return <><dt>{name}</dt><dd>{build ? fmtDate(new Date(build * 1000).toISOString()) : "Нет загруженной приложением копии"}</dd></>;
}
