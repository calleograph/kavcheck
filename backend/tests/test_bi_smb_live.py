"""Настоящий SMB-сервер (Samba, общий ресурс только на чтение): вход и диалект, неверный пароль, нет ресурса, выбор и стабильное копирование, импорт через службу worker.

Запуск: BI_SMB_TEST_HOST=<адрес> BI_SMB_TEST_USER=svcbi BI_SMB_TEST_PASS=... pytest tests/test_bi_smb_live.py (ресурс `bi` с файлом computers.xlsx структуры выгрузки)."""
import os
import uuid

import pytest
from sqlalchemy import select

from app.bi import service as SV
from app.bi import smb as S
from app.models import BiDevice, BiSource
from tests.test_bi_import import source

HOST = os.environ.get("BI_SMB_TEST_HOST")
pytestmark = pytest.mark.skipif(not HOST, reason="нет тестового SMB-сервера (BI_SMB_TEST_HOST)")
USER, PASS = os.environ.get("BI_SMB_TEST_USER", "svcbi"), os.environ.get("BI_SMB_TEST_PASS", "")


def conn(**kw):
    return S.Conn(**{"host": HOST, "share": "bi", "username": USER, "password": PASS, "encrypt": True, **kw})


def test_diagnose_ok_wrong_password_and_missing_share():
    r = S.diagnose(conn(), "fixed", "computers.xlsx", [])
    assert r["ok"] and [s["stage"] for s in r["stages"]] == ["allowed", "tcp", "auth", "list", "choose", "read"]
    assert "SMB 3" in r["stages"][2]["message"]
    bad = S.diagnose(conn(password="wrong-password"), "fixed", "computers.xlsx", [])
    assert not bad["ok"] and bad["stages"][-1]["stage"] == "auth" and "wrong-password" not in str(bad)
    miss = S.diagnose(conn(share="nope"), "fixed", "computers.xlsx", [])
    assert not miss["ok"] and miss["stages"][-1]["stage"] == "list"
    deny = S.diagnose(conn(), "fixed", "computers.xlsx", ["files.example.local"])
    assert not deny["ok"] and deny["stages"][0]["stage"] == "allowed"
    nofile = S.diagnose(conn(), "fixed", "absent.xlsx", [])
    assert not nofile["ok"] and nofile["stages"][-1]["stage"] == "choose"


def test_stable_copy(tmp_path):
    with S.Smb(conn()) as s:
        hit, _c, _w = S.choose(s.listing(), "auto", "*.xlsx")
        fi = S.fetch_stable(s, hit.name, tmp_path / "x.xlsx", 50 * 1024 * 1024, 1)
    assert fi.size == (tmp_path / "x.xlsx").stat().st_size > 0


async def test_import_through_worker_service(app):
    sid = await source(app)
    async with app.state.session_maker() as db:
        s = await db.get(BiSource, sid)
        s.smb_host, s.smb_share, s.username = HOST, "bi", USER
        s.password_enc = app.state.settings_svc.encrypt(PASS, f"bi.{sid}")
        await db.commit()
    imp = await SV.BiService(app.state.session_maker, app.state.settings, app.state.settings_svc).run_source(sid)
    assert imp.status in ("ok", "partial"), imp.message
    async with app.state.session_maker() as db:
        n = len((await db.execute(select(BiDevice).where(BiDevice.source_id == sid))).scalars().all())
    assert n > 0
    again = await SV.BiService(app.state.session_maker, app.state.settings, app.state.settings_svc).run_source(sid)
    assert again.status == "unchanged"
    _ = uuid
