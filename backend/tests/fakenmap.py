#!/usr/bin/env python3
"""Подставной Nmap для тестов конвейера: сценарий из файла FAKE_NMAP_SCENARIO (JSON), журнал запусков — FAKE_NMAP_LOG. Понимает этапы: -sn (обнаружение), порты, -sV (сервисы)."""
import json
import os
import sys
import time
from xml.sax.saxutils import quoteattr

a = sys.argv[1:]
val = lambda f: a[a.index(f) + 1] if f in a else None  # noqa: E731
if "--version" in a:
    print("Nmap version 7.98 ( https://example.org )")
    sys.exit(0)
targets = [x.strip() for x in open(val("-iL")).read().split() if x.strip()]
stage = "discovery" if "-sn" in a else "services" if "-sV" in a else "ports"
sc = json.load(open(os.environ["FAKE_NMAP_SCENARIO"]))
with open(os.environ["FAKE_NMAP_LOG"], "a") as f:
    f.write(json.dumps({"stage": stage, "targets": targets, "args": a}) + "\n")
for ip in targets:
    spec = sc.get(ip, {})
    if spec.get("hang") == stage:
        time.sleep(600)
    if spec.get("fail") == stage:
        print("Failed to resolve", file=sys.stderr)
        sys.exit(1)
want = (val("-p") or "").split(",") if stage == "services" else None
out = ['<?xml version="1.0"?><nmaprun scanner="nmap" version="7.98">']
for ip in targets:
    spec = sc.get(ip, {"up": False})
    up = spec.get("up", True)
    if stage == "discovery" and not up:
        continue
    out.append(f'<host><status state="{"up" if up else "down"}"/><address addr="{ip}" addrtype="ipv4"/>')
    if spec.get("name"):
        out.append(f'<hostnames><hostname name="{spec["name"]}" type="PTR"/></hostnames>')
    if stage != "discovery":
        out.append("<ports>")
        for p in spec.get("ports", []):
            if want is not None and str(p["port"]) not in want:
                continue
            if stage == "ports":
                out.append(f'<port protocol="tcp" portid="{p["port"]}"><state state="open"/><service name={quoteattr(p.get("service", ""))} method="table" conf="3"/></port>')
            else:
                cpe = f'<cpe>{p["cpe"]}</cpe>' if p.get("cpe") else ""
                banner = f'<script id="banner" output={quoteattr(p["banner"])}/>' if p.get("banner") else ""
                scripts = "".join(f'<script id="{s["id"]}" output={quoteattr(s.get("output", ""))}><elem key="state">{s["state"]}</elem><table key="ids">{"".join("<elem>CVE:" + c + "</elem>" for c in s.get("ids", []))}</table></script>' for s in p.get("scripts", []))
                out.append(f'<port protocol="tcp" portid="{p["port"]}"><state state="open"/><service name={quoteattr(p.get("service", ""))} product={quoteattr(p.get("product", ""))} '
                           f'version={quoteattr(p.get("version", ""))} extrainfo={quoteattr(p.get("extrainfo", ""))} method="probed" conf="10">{cpe}</service>{banner}{scripts}</port>')
        out.append("</ports>")
    out.append("</host>")
out.append("</nmaprun>")
open(val("-oX"), "w").write("".join(out))
