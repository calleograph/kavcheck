import type { Me } from "../api";
import { ThemePicker } from "../components/ThemePicker";
import { PageHead } from "../components/ui";
import { THEMES, isTheme, type ThemeId } from "../theme";

/** «Внешний вид» в профиле: личная тема применяется сразу, хранится в профиле (действует на всех устройствах) и важнее темы системы. */
export default function AppearancePage({ me, onTheme }: { me: Me; onTheme: (id: ThemeId | null) => void }) {
  const def = THEMES.find((t) => t.id === me.default_theme)?.name ?? "Тёмный профессиональный";
  return (
    <section>
      <PageHead title="Внешний вид" lede="Тема оформления применяется сразу и сохраняется в вашем профиле: она будет действовать на других устройствах и после повторного входа. Отчёты HTML и PDF оформляются одинаково при любой теме." />
      <div className="card">
        <ThemePicker label="Тема оформления" value={isTheme(me.theme) ? me.theme : null} onChange={onTheme} none={`тема по умолчанию: «${def}» (её задаёт администратор)`} />
      </div>
    </section>
  );
}
