"""Недорогие показатели процесса, контейнера и хоста для раздела «Техническое состояние».

Только чтение /proc и cgroup v2 (микросекунды), без внешних программ и без постоянного опроса: проценты CPU считаются по разности двух чтений
между тактами пульса службы. В контейнере /proc/stat, /proc/loadavg, /proc/meminfo и /proc/pressure показывают хост, cgroup — этот контейнер,
/proc/<pid> — только процессы контейнера. Недоступное (нет cgroup v2, другой каталог) — None: интерфейс пишет «нет данных», а не ноль.
"""
from __future__ import annotations

import os
import socket
import time
from collections import deque
from typing import Any

PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
TICK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
HOST = socket.gethostname()                                      # имя хоста контейнера = начало владельца аренды задания (кто исполнитель)


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def _kv(text: str | None) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in (text or "").splitlines():
        p = line.split()
        if len(p) >= 2 and p[1].lstrip("-").isdigit():
            out[p[0]] = int(p[1])
    return out


def cpu_times(root: str = "/proc") -> tuple[int, int] | None:
    """(занято, всего) тиков процессора хоста."""
    for line in (_read(f"{root}/stat") or "").splitlines():
        if line.startswith("cpu "):
            try:
                v = [int(x) for x in line.split()[1:9]]
            except ValueError:
                return None
            idle = v[3] + v[4]                                   # idle + iowait
            return sum(v) - idle, sum(v)
    return None


def loadavg(root: str = "/proc") -> list[float] | None:
    try:
        return [float(x) for x in (_read(f"{root}/loadavg") or "").split()[:3]] or None
    except ValueError:
        return None


def meminfo(root: str = "/proc") -> dict[str, int] | None:
    m: dict[str, int] = {}
    for line in (_read(f"{root}/meminfo") or "").splitlines():
        k, _, v = line.partition(":")
        try:
            m[k] = int(v.split()[0]) * 1024
        except (ValueError, IndexError):
            continue
    if "MemTotal" not in m:
        return None
    return {"total": m["MemTotal"], "available": m.get("MemAvailable"), "swap_total": m.get("SwapTotal"), "swap_free": m.get("SwapFree")}


def pressure(path: str) -> float | None:
    """PSI: доля времени за 10 с, когда хотя бы одна задача ждала ресурс (some avg10), %. Надёжнее «загрузки диска» в процентах: показывает, что работа реально ждёт."""
    for line in (_read(path) or "").splitlines():
        if line.startswith("some"):
            for part in line.split():
                if part.startswith("avg10="):
                    try:
                        return float(part[6:])
                    except ValueError:
                        return None
    return None


def cgroup(root: str = "/sys/fs/cgroup") -> dict[str, Any] | None:
    """Ресурсы этого контейнера (cgroup v2). Лимит CPU — в ядрах (cpu.max), лимит памяти — байты; «max» — без лимита (None)."""
    cpu = _kv(_read(f"{root}/cpu.stat"))
    cur = _read(f"{root}/memory.current")
    if not cpu and cur is None:
        return None

    def num(name: str) -> int | None:
        t = (_read(f"{root}/{name}") or "").strip()
        return int(t) if t.isdigit() else None
    lim_cpu = None
    q = (_read(f"{root}/cpu.max") or "").split()
    if len(q) == 2 and q[0].isdigit() and q[1].isdigit() and int(q[1]):
        lim_cpu = round(int(q[0]) / int(q[1]), 2)
    ev = _kv(_read(f"{root}/memory.events"))
    return {"cpu_usec": cpu.get("usage_usec"), "throttled_usec": cpu.get("throttled_usec"), "cpu_limit": lim_cpu, "mem": num("memory.current"), "mem_limit": num("memory.max"),
            "mem_peak": num("memory.peak"), "oom": ev.get("oom"), "oom_kill": ev.get("oom_kill"), "pids": num("pids.current"), "pids_limit": num("pids.max"),
            "io_pressure": pressure(f"{root}/io.pressure"), "mem_pressure": pressure(f"{root}/memory.pressure"), "cpu_pressure": pressure(f"{root}/cpu.pressure")}


def processes(root: str = "/proc") -> dict[int, tuple[str, int, int, int]]:
    """Процессы, видимые этой службе (в контейнере — только свои): pid → (имя, тики CPU, потоки, RSS байт)."""
    out: dict[int, tuple[str, int, int, int]] = {}
    try:
        pids = [int(p) for p in os.listdir(root) if p.isdigit()]
    except OSError:
        return out
    for pid in pids[:400]:                                       # shortcut: не больше 400 процессов; в контейнерах KAV Checker их единицы
        st = _read(f"{root}/{pid}/stat")
        if not st or ")" not in st:
            continue
        name = st[st.find("(") + 1:st.rfind(")")]
        f = st[st.rfind(")") + 2:].split()
        try:
            out[pid] = (name[:40], int(f[11]) + int(f[12]), int(f[17]), int(f[21]) * PAGE)
        except (IndexError, ValueError):
            continue
    return out


class Sampler:
    """Замер раз в такт пульса службы. CPU — по разности с прошлым замером; история — последние `keep` точек (при такте 15 с — около часа), не растёт.
    `high_since` — с какого момента контейнер непрерывно выше `high_pct` (100 % = одно ядро), чтобы показывать длительность высокой нагрузки."""

    def __init__(self, proc_root: str = "/proc", cg_root: str = "/sys/fs/cgroup", keep: int = 240, high_pct: float = 85.0) -> None:
        self.proc, self.cg, self.high_pct = proc_root, cg_root, high_pct
        self.hist: deque[list] = deque(maxlen=keep)
        self._cpu: tuple[int, int] | None = None
        self._cg: tuple[float, int] | None = None
        self._procs: tuple[float, dict[int, tuple[str, int, int, int]]] | None = None
        self.high_since: float | None = None
        self.last: dict[str, Any] = {}

    def sample(self) -> dict[str, Any]:
        now = time.time()
        host_pct = None
        cur = cpu_times(self.proc)
        if cur and self._cpu and cur[1] > self._cpu[1]:
            host_pct = round(100.0 * (cur[0] - self._cpu[0]) / (cur[1] - self._cpu[1]), 1)
        self._cpu = cur or self._cpu
        cg = cgroup(self.cg)
        cg_pct = None
        if cg and cg["cpu_usec"] is not None:
            if self._cg and now > self._cg[0]:
                cg_pct = round(max(0.0, (cg["cpu_usec"] - self._cg[1]) / 1e6 / (now - self._cg[0]) * 100), 1)
            self._cg = (now, cg["cpu_usec"])
        procs = processes(self.proc)
        top = []
        if self._procs and now > self._procs[0]:
            dt = now - self._procs[0]
            for pid, (name, ticks, thr, rss) in procs.items():
                prev = self._procs[1].get(pid)
                pct = round((ticks - prev[1]) / TICK / dt * 100, 1) if prev and prev[0] == name else None
                top.append({"pid": pid, "name": name, "cpu_pct": pct, "threads": thr, "rss": rss})
            top.sort(key=lambda p: (p["cpu_pct"] or 0, p["rss"]), reverse=True)
        self._procs = (now, procs)
        if cg_pct is not None:
            self.high_since = (self.high_since or now) if cg_pct >= self.high_pct else None
        mem = meminfo(self.proc)
        self.last = {"at": now, "host": HOST, "cpus": os.cpu_count() or 1, "host_cpu_pct": host_pct, "load": loadavg(self.proc), "mem": mem,
                     "host_io_pressure": pressure(f"{self.proc}/pressure/io"), "host_mem_pressure": pressure(f"{self.proc}/pressure/memory"),
                     "cgroup": cg, "cpu_pct": cg_pct, "high_since": self.high_since, "threads": sum(p[2] for p in procs.values()), "procs": len(procs), "top": top[:5]}
        self.hist.append([int(now), host_pct, cg_pct, cg["mem"] if cg else None])
        return self.last

    def snapshot(self) -> dict[str, Any]:
        """Для пульса службы: последний замер и история (компактно: [время, CPU хоста %, CPU контейнера %, память байт])."""
        return {**self.last, "hist": list(self.hist)}
