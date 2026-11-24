import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { qs, req } from "../api";

export function WorkplaceLink({ deviceId, employeeId, className }: { deviceId?: string; employeeId?: string; className?: string }) {
  const [allowed, setAllowed] = useState(false);
  useEffect(() => {
    let active = true;
    req<{ allowed: boolean }>("GET", "/employee-protection/access").then((r) => {
      if (active) setAllowed(r.allowed);
    }).catch(() => {});
    return () => { active = false; };
  }, []);
  return allowed ? <Link className={className} to={`/employee-protection${qs({ view: "workplaces", device_id: deviceId, employee_id: employeeId })}`}>Рабочие места</Link> : null;
}
