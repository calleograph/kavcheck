import { afterEach, describe, expect, it, vi } from "vitest";
import { api, setAllSources, setSourceId } from "../api";
import { workplaceDeviceHref, workplaceHref } from "./WorkplaceLink";

const selected = "00000000-0000-0000-0000-000000000001";
const target = "00000000-0000-0000-0000-000000000002";

afterEach(() => {
  vi.unstubAllGlobals();
  setAllSources(false);
  setSourceId(null);
});

describe("рабочие места", () => {
  it("выбирает карточку подтверждённого учёта, KSC или BI по данным устройства", () => {
    const device = { id: `ksc:${target}:17`, source_id: target, host_id: 17, asset_id: 4 };
    expect(workplaceDeviceHref(device)).toBe(`/devices?card=${target}:17`);
    expect(workplaceDeviceHref({ ...device, ownership_asset_id: 4 }, "place")).toBe("/inventory/assets/4?tab=place");
    expect(workplaceDeviceHref({ id: "inv:5", asset_id: 5 })).toBe("/inventory/assets/5");
    expect(workplaceDeviceHref({ id: "bi:6" })).toBe("/devices?tab=bi&bidev=6");
    const scope = new URL(workplaceHref(device.id, "example"), "https://example.local");
    expect(Object.fromEntries(scope.searchParams)).toEqual({ view: "workplaces", device_id: device.id, employee_id: "example" });
  });

  it("отправляет запрос карточки в её источник, сохраняя режим списка", async () => {
    const fetch = vi.fn(async (_url: string, _options: RequestInit) => new Response("{}"));
    vi.stubGlobal("fetch", fetch);
    setSourceId(selected);

    await api.devices.card(target, 17);
    await api.devices.list({});
    setAllSources(true);
    await api.devices.card(target, 17);
    await api.devices.list({});

    expect(fetch.mock.calls.map(([_, options]) => new Headers(options.headers).get("X-Source-Id")))
      .toEqual([target, selected, target, "all"]);
  });
});
