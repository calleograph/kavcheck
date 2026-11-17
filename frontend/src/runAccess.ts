import { createContext, useContext } from "react";

/** Запуск и остановка проверок (Pentest, CVE Hunt) — роль «Специалист по ИБ» и выше; страницы только просматривают результаты для остальных. */
export const RunAccess = createContext(false);
export const useCanRun = () => useContext(RunAccess);
