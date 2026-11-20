/** Роли KAV Checker и что каждая открывает: справка рядом с выбором роли (правила доступа, локальные пользователи). */
export const ROLE_OPTIONS: { id: "viewer" | "analyst" | "security" | "admin"; label: string; can: string }[] = [
  { id: "viewer", label: "Просмотр", can: "Панели, компьютеры, защита, события, уязвимости, EOL, устройства, лицензии, зоны и «Иерархия предприятия» — только чтение." },
  { id: "analyst", label: "Аналитик", can: "Всё из «Просмотра», а также отчёты и выгрузки, решения по уязвимостям, сопоставление с BI, вкладка Active Directory, результаты Pentest и CVE Hunt." },
  { id: "security", label: "Специалист по ИБ", can: "Всё из «Аналитика», а также запуск и остановка Pentest и CVE Hunt, проверка OVAL, связывание адресов с устройствами KSC, аудит домена с каталогом AD (каталог — независимо от настроек «Иерархии»)." },
  { id: "admin", label: "Администратор", can: "Всё из «Специалиста по ИБ», а также администрирование: источники, пользователи, доступ, настройки, обновления." },
];

export function RoleGuide() {
  return (
    <div className="table-scroll">
      <table className="table role-guide">
        <caption className="sr-only">Возможности ролей</caption>
        <thead><tr><th>Роль</th><th>Что доступно</th></tr></thead>
        <tbody>{ROLE_OPTIONS.map((r) => <tr key={r.id}><td className="nowrap"><b>{r.label}</b></td><td className="small">{r.can}</td></tr>)}</tbody>
      </table>
      <p className="muted small">Ответственный за зону не выбирается здесь: он назначается в разделе «Зоны» и видит только свои зоны.</p>
    </div>
  );
}

export const RoleSelect = ({ value, onChange, disabled }: { value: string; onChange: (v: "viewer" | "analyst" | "security" | "admin") => void; disabled?: boolean }) => (
  <select value={value} onChange={(e) => onChange(e.target.value as "viewer")} disabled={disabled}>{ROLE_OPTIONS.map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}</select>
);
