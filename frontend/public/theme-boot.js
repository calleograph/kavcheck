/* Тема до первой отрисовки, без вспышки чужой схемы (отдельный файл: политика CSP разрешает только свои скрипты).
   Порядок: личный выбор (kc:theme) → тема по умолчанию системы, запомненная при прошлом визите (kc:theme-default) → «Тёмный профессиональный».
   Прежние значения светлой и тёмной схем переносятся на ближайшие темы. */
(function () {
  var ok = /^(glass|night|grove|aurora)$/, legacy = { light: "glass", dark: "night" }, t = "night";
  try {
    var v = localStorage.getItem("kc:theme"), d = localStorage.getItem("kc:theme-default");
    if (ok.test(v)) t = v; else if (legacy[v]) t = legacy[v]; else if (ok.test(d)) t = d;
  } catch (e) { /* без хранилища — тема по умолчанию */ }
  document.documentElement.setAttribute("data-theme", t);
})();
