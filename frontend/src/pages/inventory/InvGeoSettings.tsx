import { useEffect, useState } from "react";
import { req } from "../../api";
import { Icon } from "../../components/Icons";
import { SkelRows } from "../../components/ui";
import { fmt, fmtDate } from "../../util";

interface Status {
  enabled: boolean; account_id: string; license_key_set: boolean;
  running: boolean; pending: boolean; stage: string; checked_at: string | null; success_at: string | null;
  next_check_at: string | null; error: string;
  databases: Record<string, { build_epoch: number; last_modified: string }>;
}
const PATH = "/inv/geography/geoip";

export default function InvGeoSettings() {
  const [status, setStatus] = useState<Status | null>(null);
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
      if (active) { setStatus(s); setAccount(s.account_id); setEnabled(s.enabled); setError(""); }
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

  const dirty = status && (status.enabled !== enabled || status.account_id !== account.trim() || Boolean(key.trim()) || clear);
  const save = async () => {
    setBusy(true); setError(""); setNotice("");
    try {
      await req("PUT", "/admin/settings/geoip", { enabled, account_id: account.trim(),
        ...(clear ? { license_key: "" } : key.trim() ? { license_key: key.trim() } : {}) });
      setKey(""); setClear(false);
      setStatus(await req<Status>("GET", PATH));
      setNotice(enabled ? "Настройки сохранены. Worker проверит базы." : "Настройки сохранены.");
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

  const names = ["GeoLite2-City", "GeoLite2-ASN"];
  return <div className="split even">
    <form className="card form-stack" onSubmit={(e) => { e.preventDefault(); void save(); }}>
      <h2>GeoLite2</h2>
      <p className="small muted">Укажите учётную запись и ключ MaxMind. Worker загрузит базы City и ASN, а поиск по IP будет выполняться локально.</p>
      <label className="field">Номер учётной записи<input value={account} onChange={(e) => setAccount(e.target.value)}
        inputMode="numeric" autoComplete="off" pattern="[0-9]*" maxLength={18} disabled={busy} /></label>
      <label className="field">Лицензионный ключ<input type="password" value={key} onChange={(e) => setKey(e.target.value)}
        autoComplete="new-password" maxLength={128} disabled={busy || clear} placeholder={status.license_key_set ? "Сохранён" : ""} /></label>
      <label className="check-row"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)}
        disabled={busy || clear} />Автоматически загружать и обновлять базы</label>
      {status.license_key_set && <label className="check-row"><input type="checkbox" checked={clear} disabled={busy}
        onChange={(e) => { setClear(e.target.checked); if (e.target.checked) { setKey(""); setEnabled(false); } }} />Удалить ключ при сохранении</label>}
      <div className="row wrap">
        <button className="btn primary" type="submit" disabled={!dirty || busy}><Icon name="save" size={16} />Сохранить настройки GeoLite2</button>
        <button className="btn" type="button" disabled={!!dirty || busy || checking || !status.account_id || !status.license_key_set}
          onClick={() => void refresh()}><Icon name="refresh" size={16} />Проверить и загрузить сейчас</button>
      </div>
      {error && <p className="field-err" role="alert">{error}</p>}
      {notice && <p role="status">{notice}</p>}
    </form>
    <section className="card stack">
      <h2>Управляемые базы</h2>
      <p role="status">{status.running ? status.stage || "Проверка GeoLite2" : status.pending ? "Ожидает worker" :
        status.enabled ? "Автоматическая проверка включена" : "Автоматическая проверка выключена"}</p>
      {status.error && <p className="field-err" role="alert">{status.error}</p>}
      <dl className="kv">
        <dt>Последняя проверка</dt><dd>{fmt(status.checked_at)}</dd>
        <dt>Последняя успешная проверка</dt><dd>{fmt(status.success_at)}</dd>
        {status.enabled && <><dt>Следующая проверка</dt><dd>{fmt(status.next_check_at)}</dd></>}
        {names.map((name) => <DatabaseDate key={name} name={name} build={status.databases[name]?.build_epoch} />)}
      </dl>
      <p className="small muted">Ручные базы можно разместить в каталоге GeoIP установки. Файлы, загруженные приложением, сохраняются при сетевой ошибке.</p>
      <a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/" target="_blank" rel="noreferrer">Учётная запись и условия GeoLite2</a>
    </section>
  </div>;
}

function DatabaseDate({ name, build }: { name: string; build?: number }) {
  return <><dt>{name}</dt><dd>{build ? fmtDate(new Date(build * 1000).toISOString()) : "Нет загруженной приложением копии"}</dd></>;
}
