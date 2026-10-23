/* Тема пользователя до загрузки приложения: без вспышки другой схемы. Отдельный файл: политика CSP разрешает только свои скрипты. */
try { var t = localStorage.getItem("kc:theme"); if (t && t !== "system") document.documentElement.setAttribute("data-theme", t); } catch (e) { /* по системе */ }
