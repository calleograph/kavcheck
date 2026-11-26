import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { qs, req } from "../api";

export function workplaceHref(deviceId?: string, employeeId?: string) {
  return `/employee-protection${qs({ view: "workplaces", device_id: deviceId, employee_id: employeeId })}`;
}

export function workplaceDeviceHref(d: { id: string; asset_id?: number | null; ownership_asset_id?: number | null; source_id?: string | null; host_id?: number | null }, tab?: "place") {
  const assetId = d.ownership_asset_id ?? (d.id.startsWith("inv:") ? d.asset_id : null);
  if (assetId) return `/inventory/assets/${assetId}${qs({ tab })}`;
  if (d.source_id && d.host_id != null) return `/devices?card=${d.source_id}:${d.host_id}`;
  if (/^bi:[1-9]\d*$/.test(d.id)) return `/devices${qs({ tab: "bi", bidev: d.id.slice(3) })}`;
  return null;
}

export function WorkplaceLink({ deviceId, employeeId, className }: { deviceId?: string; employeeId?: string; className?: string }) {
  const [allowed, setAllowed] = useState(false);
  useEffect(() => {
    let active = true;
    req<{ allowed: boolean }>("GET", "/employee-protection/access").then((r) => {
      if (active) setAllowed(r.allowed);
    }).catch(() => {});
    return () => { active = false; };
  }, []);
  return allowed ? <Link className={className} to={workplaceHref(deviceId, employeeId)}>Рабочие места</Link> : null;
}
