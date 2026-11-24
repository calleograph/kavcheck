export const DB_IP_LITE = "DB-IP Lite";
export const DB_IP_CREDIT = "IP Geolocation by DB-IP";

export function DbIpAttribution() {
  return <><a href="https://db-ip.com" target="_blank" rel="noreferrer">{DB_IP_CREDIT}</a>{" · "}
    <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noreferrer">CC BY 4.0</a></>;
}
