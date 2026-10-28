#!/usr/bin/env python3
"""Подставной Nuclei: читает сценарий FAKE_NUCLEI_SCENARIO (JSON: {"hits": [{host, template-id, severity, tags, cve, matched-at, matcher, port, type, response}], "hang": bool}),
пишет JSONL в stdout, журнал запусков — FAKE_NUCLEI_LOG. Как настоящий, зависает на непустом stdin (проверка, что запуск закрывает stdin)."""
import json
import os
import sys
import time

a = sys.argv[1:]
val = lambda f: a[a.index(f) + 1] if f in a else None  # noqa: E731
if "-version" in a:
    print("[INF] Nuclei Engine Version: v3.11.1")
    sys.exit(0)
if not sys.stdin.isatty() and os.environ.get("FAKE_NUCLEI_STDIN_CHECK", "1") == "1":
    if sys.stdin.read(1):
        time.sleep(600)
sc = json.load(open(os.environ["FAKE_NUCLEI_SCENARIO"]))
targets = [x.strip() for x in open(val("-l")).read().split() if x.strip()]
tmpl = [x.strip() for x in open(val("-t")).read().split() if x.strip()]
with open(os.environ["FAKE_NUCLEI_LOG"], "a") as f:
    f.write(json.dumps({"args": a, "targets": targets, "templates": tmpl, "env": {k: os.environ.get(k, "") for k in ("HOME", "GOMEMLIMIT")}}) + "\n")
if sc.get("hang"):
    time.sleep(600)
if sc.get("fail"):
    print("fatal", file=sys.stderr)
    sys.exit(2)
ids = {os.path.basename(t)[:-5] for t in tmpl}
for h in sc.get("hits", []):
    if h["template-id"] not in ids:
        continue
    ip = h["host"]
    if not any(t.split("://", 1)[-1].rsplit(":", 1)[0].strip("[]") == ip for t in targets):
        continue
    d = {"template-id": h["template-id"], "info": {"name": h.get("name", h["template-id"]), "severity": h.get("severity", "info"), "tags": h.get("tags", []),
                                                   "classification": {"cve-id": h.get("cve", [])}, "description": h.get("description", ""), "remediation": h.get("remediation", ""), "reference": h.get("reference", [])},
         "type": h.get("type", "http"), "host": ip, "ip": ip, "port": str(h.get("port", 80)), "matched-at": h.get("matched-at", f"http://{ip}:{h.get('port', 80)}"), "matcher-name": h.get("matcher", ""),
         "extracted-results": h.get("extracted", []), "response": h.get("response", "")}
    print(json.dumps(d))
