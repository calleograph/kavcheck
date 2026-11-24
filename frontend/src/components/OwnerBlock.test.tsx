import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import type { BiOwnerBrief } from "../api";
import { OwnerSub } from "./OwnerBlock";

it.each([false, true])("показывает полное имя владельца в подсказке (compact=%s)", (compact) => {
  const owner: BiOwnerBrief = { name: "Александрова Александра Александровна", department: "Отдел учёта", email: "",
    state: "current", state_ru: "Владелец по карточке учёта", level: "inv", multi: false, seen_at: "" };
  const html = renderToStaticMarkup(<OwnerSub o={owner} compact={compact} />);
  expect(html).toContain(`title="${owner.name} · ${owner.state_ru} · ${owner.department}"`);
});
