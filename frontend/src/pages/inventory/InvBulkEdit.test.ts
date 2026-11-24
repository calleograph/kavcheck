import { expect, it } from "vitest";
import { filtersForBulk, toggleAssetMarks } from "./InvBulkEdit";

it("сохраняет выбранные карточки при отметке и снятии отметки другой страницы", () => {
  const previous = new Set([3, 101]);
  const marked = toggleAssetMarks(previous, [101, 102], false);
  expect([...marked]).toEqual([3, 101, 102]);
  expect([...toggleAssetMarks(marked, [101, 102], false)]).toEqual([3]);
  expect([...previous]).toEqual([3, 101]);
});

it("для всей выборки хранит лишь исключения и восстанавливает отметки неполной страницы", () => {
  const excluded = new Set([5, 101]);
  const included = toggleAssetMarks(excluded, [101, 102], true);
  expect([...included]).toEqual([5]);
  expect([...toggleAssetMarks(included, [101, 102], true)]).toEqual([5, 101, 102]);
});

it("передаёт в массовую операцию те же фильтры, включая дополнительные свойства", () => {
  expect(filtersForBulk({ q: "принтер", location: "11", "p.remote": "false" })).toEqual({ q: "принтер", location: "11", props: { remote: "false" } });
  expect(filtersForBulk({})).toEqual({ props: {} });
});
