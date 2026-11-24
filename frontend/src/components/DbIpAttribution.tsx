export const DB_IP_LITE = "DB-IP Lite";
export const DB_IP_CREDIT = "IP Geolocation by DB-IP";
export const GEOLITE = "GeoLite2";
export const GEOLITE_CREDIT = "Геоданные GeoLite от MaxMind";

export function DbIpAttribution() {
  return <><a href="https://db-ip.com" target="_blank" rel="noreferrer">{DB_IP_CREDIT}</a>{" · "}
    <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noreferrer">CC BY 4.0</a></>;
}

export function GeoIpAttribution({ provider }: { provider: string }) {
  if (provider === DB_IP_LITE) return <DbIpAttribution />;
  if (provider !== GEOLITE) return <>{provider}</>;
  return <><a href="https://www.maxmind.com/" target="_blank" rel="noreferrer">{GEOLITE_CREDIT}</a>{" · "}
    <a href="https://www.maxmind.com/en/geolite/eula" target="_blank" rel="noreferrer">Лицензия GeoLite</a></>;
}

export function geoCreditProvider(note: string) {
  if (note.startsWith(DB_IP_CREDIT)) return DB_IP_LITE;
  if (note.startsWith(GEOLITE_CREDIT)) return GEOLITE;
  return "";
}
