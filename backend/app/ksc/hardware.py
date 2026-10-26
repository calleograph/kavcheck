"""Оборудование компьютера по инвентаризации Агента (таблица `hst_hwinv_dev` базы KSC) и контроль ресурсов Linux-серверов.

Что даёт KSC: по строке на компонент (процессор: ядра, потоки, частота; модули ОЗУ: объём; накопители: объём и свободное место; сетевые адаптеры, плата, BIOS, видео, монитор).
Чего нет или может не быть: сведений для компьютеров, где инвентаризация не собрана; различия «диск / раздел / том» в явном виде — поэтому логические тома, разделы, loop- и ram-устройства
определяются по названию и в «физический» итог не входят (иначе объём считался бы дважды). Оценка достаточности ресурсов — только для Linux и только если данные есть."""
from __future__ import annotations

import re

from ..search import matcher

TYPES = {0: "Системная плата", 1: "Процессор", 2: "Модуль ОЗУ", 3: "Накопитель", 4: "Видеоадаптер", 5: "Звуковое устройство", 6: "Сетевой адаптер", 7: "Монитор", 8: "Привод"}
# логический объект, а не физический диск: раздел, том LVM/device-mapper, массив md, loop/ram/zram, снимок, точка монтирования
_LOGICAL = re.compile(r"(?:^|[\s/\\_-])(?:dm-\d+|loop\d*|ram\d*|zram\d*|md\d+|sr\d+|nbd\d+)\b|\b(?:sd[a-z]+\d+|vd[a-z]+\d+|xvd[a-z]+\d+|hd[a-z]+\d+|nvme\d+n\d+p\d+|mmcblk\d+p\d+)\b|lvm|logical volume|device.?mapper|volume|раздел|том\b|partition|mount|tmpfs|overlay",
                      re.I)


def is_logical(name: str, descr: str, dev_id: str) -> bool:
    return bool(_LOGICAL.search(" ".join(x for x in (name, descr, dev_id) if x)))


def _gb(b) -> float | None:
    return round(int(b) / 1e9, 1) if b else None


def summarize(rows: list[dict]) -> dict:
    """Сводка оборудования одного компьютера из строк `HW_HOST`. Нет строк — `known = False` (на странице «Нет данных»)."""
    cpus, rams, disks, logical, nics, other = [], [], [], [], [], []
    seen: set[tuple] = set()
    bios = None
    for r in rows:
        t, name = int(r["dev_type"] or 0), (r.get("name") or "").strip()
        key = (t, r.get("dev_id") or name, r.get("serial") or r.get("x1") or "", r.get("x2"), r.get("x3"))
        if key in seen:                               # повторные строки одного компонента не удваивают итоги
            continue
        seen.add(key)
        if t == 1:
            cpus.append({"name": name, "manuf": r.get("manuf") or "", "mhz": r.get("cpu_mhz"), "cores": r.get("cpu_cores"), "threads": r.get("cpu_threads")})
        elif t == 2:
            rams.append({"name": name or "Модуль ОЗУ", "mb": int(r["x3"]) // 1048576 if r.get("x3") else None, "mhz": r.get("x2") or None})
        elif t == 3:
            d = {"name": name, "descr": r.get("descr") or "", "manuf": r.get("manuf") or "", "serial": (r.get("x1") or r.get("serial") or ""), "total_gb": _gb(r.get("x2")), "free_gb": _gb(r.get("x3")),
                 "total": int(r["x2"]) if r.get("x2") else 0, "free": int(r["x3"]) if r.get("x3") else None}
            (logical if is_logical(name, r.get("descr") or "", r.get("dev_id") or "") else disks).append(d)
        elif t == 6:
            nics.append({"name": name, "mac": r.get("x1") or "", "speed_mbit": int(r["x2"]) // 1_000_000 if r.get("x2") else None})
        elif t == 0:
            bios = {"board": name, "manuf": r.get("manuf") or "", "bios_manuf": r.get("bios_manuf") or "", "bios_version": r.get("bios_version") or "", "bios_date": r.get("bios_date")}
        elif t in (4, 5, 7, 8):
            other.append({"type": TYPES[t], "name": name})
    known_cores = [c for c in cpus if c["cores"]]
    cores = sum(int(c["cores"]) for c in known_cores) if known_cores else None
    threads = sum(int(c["threads"] or 0) for c in known_cores) or None if known_cores else None
    ram_mb = sum(m["mb"] or 0 for m in rams) or None
    base = disks or logical                          # физических дисков нет, но есть логические: берётся наибольший объём (чтобы не удвоить), с пометкой
    total = (sum(d["total"] for d in disks) if disks else max((d["total"] for d in logical), default=0)) or None
    frees = [d["free"] for d in base if d["free"] is not None]
    free = (sum(frees) if disks else max(frees, default=None)) if frees else None
    return {"known": bool(rows), "virtual": False, "cpus": cpus, "sockets": len(cpus) or None, "cores": cores, "threads": threads, "ram_modules": rams, "ram_mb": ram_mb, "disks": disks, "logical": logical,
            "disk_total_gb": _gb(total), "disk_free_gb": _gb(free), "disks_logical_only": bool(not disks and logical), "nics": nics, "board": bios, "other": other}


_VM = re.compile(r"hyper-v|vmware|virtualbox|qemu|kvm|xen|bochs|parallels|virtual machine|openstack|nutanix|proxmox|ovirt|cloud hypervisor", re.I)


def is_virtual(h: dict) -> bool:
    """Виртуальная машина по плате и BIOS (Hyper-V, VMware, VirtualBox, QEMU/KVM, Xen…): тогда показываются выделенные ресурсы, а не физические."""
    b = h.get("board") or {}
    return bool(_VM.search(" ".join(str(b.get(k) or "") for k in ("board", "manuf", "bios_manuf", "bios_version")) + " " + " ".join(c["name"] for c in h.get("cpus", [])[:1])))


def finish(h: dict) -> dict:
    h["virtual"] = is_virtual(h)
    h["line"] = line(h) if h["known"] else "Нет данных"
    return h


def line(h: dict) -> str:
    """Компактная строка для карточки: «Диски: 120 ГБ · CPU: 2 ядра · ОЗУ: 4 ГБ» (нет данных — «Нет данных»)."""
    nd = "Нет данных"
    disk = f"{h['disk_total_gb']:g} ГБ" if h.get("disk_total_gb") else nd
    cores = h.get("cores")
    cpu = f"{cores} {'ядро' if cores == 1 else 'ядра' if cores and 2 <= cores <= 4 else 'ядер'}" if cores else nd
    ram = (f"{h['ram_mb'] / 1024:.0f} ГБ" if h["ram_mb"] >= 1024 else f"{h['ram_mb']} МБ") if h.get("ram_mb") else nd
    return f"Диски: {disk} · CPU: {cpu} · ОЗУ: {ram}"


def aggregate_to_summary(a: dict) -> dict:
    """Сводка по агрегату `HW_AGG_*` (ядра и ОЗУ без списков компонентов) — для оценки сотен тысяч компьютеров без выгрузки компонентов."""
    known = int(a.get("cpus_known") or 0) > 0
    return {"known": True, "cores": int(a["cores"]) if known and a.get("cores") else None, "threads": int(a["threads"]) or None if known else None,
            "sockets": int(a.get("cpus") or 0) or None, "ram_mb": int(a["ram_bytes"]) // 1048576 if a.get("ram_bytes") else None}


def evaluate(hw: dict | None, cfg, name: str = "") -> list[dict]:
    """Проблемы достаточности ресурсов Linux-сервера. Нет данных о показателе — оценка по нему не выполняется (ложных предупреждений нет)."""
    if not hw or not cfg.enabled:
        return []
    skip = [matcher(m) for m in cfg.exclude_masks]
    if name and any(f and f(name) for f in skip):
        return []
    out = []
    cores = hw.get("cores")
    if cores:
        if cores <= cfg.cpu_critical_cores:
            out.append({"key": "hw_cpu", "level": "critical", "level_ru": "Критическая", "title": "Недостаточно ядер CPU", "actual": cores, "threshold": cfg.cpu_critical_cores + 1,
                        "text": f"ядер процессора: {cores}; порог критичности — {cfg.cpu_critical_cores} и меньше, норма — {cfg.cpu_ok_cores} и больше"})
        elif cores < cfg.cpu_ok_cores:
            out.append({"key": "hw_cpu", "level": "warning", "level_ru": "Предупреждение", "title": "Мало ядер CPU", "actual": cores, "threshold": cfg.cpu_ok_cores,
                        "text": f"ядер процессора: {cores}; норма — {cfg.cpu_ok_cores} и больше"})
    ram = hw.get("ram_mb")
    if ram and ram < cfg.ram_min_mb:
        out.append({"key": "hw_ram", "level": "warning", "level_ru": "Предупреждение", "title": "Недостаточно ОЗУ", "actual": ram, "threshold": cfg.ram_min_mb,
                    "text": f"ОЗУ: {ram} МБ; порог — {cfg.ram_min_mb} МБ"})
    return out


async def load_linux(client) -> dict[int, dict]:
    """Агрегаты по всем Linux-компьютерам источника одним запросом (ядра и ОЗУ)."""
    from . import queries as q  # noqa: PLC0415

    return {int(r["host_id"]): aggregate_to_summary(r) for r in await client.run(q.HW_AGG_LINUX, max_rows=500_000)}


async def load_for(client, host_ids: list[int]) -> dict[int, dict]:
    from . import queries as q  # noqa: PLC0415

    out: dict[int, dict] = {}
    for i in range(0, len(host_ids), 1000):
        for r in await client.run(q.HW_AGG_FOR.format(ids=q.ids_list(host_ids[i:i + 1000])), max_rows=5000):
            out[int(r["host_id"])] = aggregate_to_summary(r)
    return out


def attach(records: list[dict], agg: dict[int, dict], cfg) -> None:
    """Добавляет Linux-компьютерам `hw` (сводка и проблемы). Остальным — `hw = None`: правила к Windows и рабочим станциям не применяются."""
    for r in records:
        hw = agg.get(r["host_id"]) if r.get("platform") == "Linux" and cfg.enabled else None
        if hw is not None:
            hw = {**hw, "problems": evaluate(hw, cfg, r.get("name") or "")}
        r["hw"] = hw
