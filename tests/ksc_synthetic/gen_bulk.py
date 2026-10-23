#!/usr/bin/env python3
"""Генератор крупной синтетической базы «как KSC» (KAVBIG) для проверки производительности: тысячи компьютеров, сотни тысяч установок,
около миллиона обнаружений уязвимостей, сотни тысяч событий. Данные вымышленные: имена example.local, адреса из диапазона 198.18.0.0/15
(RFC 2544, для испытаний). Структура объектов — как в schema.sql. Результат — SQL для sqlcmd (stdout).

    python3 tests/ksc_synthetic/gen_bulk.py --hosts 20000 > /tmp/bulk.sql
"""
from __future__ import annotations

import argparse

# (название записи с {v}, производитель, платформа 1=Windows 2=Linux, версии от новой к старой, доля компьютеров %, уязвимый продукт VAPM или None)
FAMILIES = [
    ("Google Chrome", "Google LLC", 1, ["130.0.6723.70", "129.0.6668.90", "128.0.6613.138", "126.0.6478.127", "124.0.6367.60", "120.0.6099.130"], 92, "Google Chrome"),
    ("Microsoft Edge", "Microsoft Corporation", 1, ["130.0.2849.56", "129.0.2792.89", "127.0.2651.105", "124.0.2478.80"], 95, "Microsoft Edge"),
    ("Mozilla Firefox (x64 ru)", "Mozilla", 1, ["131.0.3", "130.0.1", "128.0.3", "125.0.3", "115.10.0"], 35, "Mozilla Firefox"),
    ("Mozilla Firefox ESR (x64 ru)", "Mozilla", 1, ["128.4.0", "115.16.0", "115.10.0"], 8, "Mozilla Firefox"),
    ("7-Zip {v} (x64)", "Igor Pavlov", 1, ["24.08", "24.07", "23.01", "22.01", "19.00"], 70, "7-Zip"),
    ("WinRAR {v} (64-bit)", "win.rar GmbH", 1, ["7.01", "6.24", "6.02", "5.91"], 30, "WinRAR"),
    ("Java 8 Update {u} (64-bit)", "Oracle Corporation", 1, ["8.0.4310.10", "8.0.4210.9", "8.0.4010.7", "8.0.3910.13", "8.0.3610.9"], 40, "Oracle Java"),
    ("Adobe Acrobat Reader DC - Russian", "Adobe", 1, ["24.003.20180", "24.002.20736", "23.008.20470", "21.001.20155"], 55, "Adobe Acrobat Reader"),
    ("Microsoft Office Professional Plus 2016", "Microsoft Corporation", 1, ["16.0.5465.1000", "16.0.5422.1000", "16.0.4266.1001"], 40, "Microsoft Office"),
    ("Microsoft 365 Apps for enterprise - ru-ru", "Microsoft Corporation", 1, ["16.0.18129.20116", "16.0.17928.20156", "16.0.17126.20132"], 45, "Microsoft Office"),
    ("Notepad++ (64-bit x64)", "Notepad++ Team", 1, ["8.7", "8.6.4", "8.5.8", "8.4.6"], 25, "Notepad++"),
    ("Python {v3} Core Interpreter (64-bit)", "Python Software Foundation", 1, ["3.13.0150.0", "3.12.7150.0", "3.11.9150.0", "3.10.11150.0"], 6, None),
    ("Python {v3} Standard Library (64-bit)", "Python Software Foundation", 1, ["3.13.0150.0", "3.12.7150.0", "3.11.9150.0", "3.10.11150.0"], 6, None),
    ("Microsoft Visual C++ 2015-2022 Redistributable (x64) - {v}", "Microsoft Corporation", 1, ["14.40.33810", "14.38.33135", "14.36.32532"], 85, None),
    ("Microsoft .NET Runtime - {v} (x64)", "Microsoft Corporation", 1, ["8.0.10", "8.0.4", "6.0.33", "6.0.25"], 50, None),
    ("Kaspersky Endpoint Security для Windows", "AO Kaspersky Lab", 1, ["12.6.0.438", "12.4.0.467", "11.11.0.452"], 96, None),
    ("Агент администрирования Kaspersky Security Center", "AO Kaspersky Lab", 1, ["15.1.0.20748", "14.2.0.26967", "14.0.0.10902"], 99, None),
    ("PuTTY release {v} (64-bit)", "Simon Tatham", 1, ["0.81", "0.80", "0.78", "0.76"], 15, "PuTTY"),
    ("Zoom Workplace (64-bit)", "Zoom Video Communications, Inc.", 1, ["6.2.5", "6.1.1", "5.17.5"], 30, None),
    ("1С:Предприятие 8 ({v})", "1С-Софт", 1, ["8.3.25.1374", "8.3.24.1691", "8.3.22.2283"], 35, None),
    ("КриптоПро CSP", "Компания КРИПТО-ПРО", 1, ["5.0.13000", "5.0.12600", "4.0.9975"], 30, None),
    # Linux
    ("php8.3-fpm", "Ubuntu Developers <team@example.org>", 2, ["8.3.6-0ubuntu0.24.04.3", "8.3.6-0ubuntu0.24.04.1"], 25, None),
    ("php7.4-cli", "Debian PHP Maintainers <team@example.org>", 2, ["7.4.33-1+deb11u7", "7.4.33-1+deb11u5", "7.4.33-1+deb11u1"], 20, None),
    ("libssl3", "Ubuntu Developers <team@example.org>", 2, ["3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.1", "3.0.2-0ubuntu1.15"], 60, None),
    ("libssl1.1", "Debian OpenSSL Team <team@example.org>", 2, ["1.1.1w-0+deb11u2", "1.1.1w-0+deb11u1", "1.1.1n-0+deb11u5"], 35, None),
    ("openssh-server", "Debian OpenSSH Maintainers <team@example.org>", 2, ["1:9.6p1-3ubuntu13.5", "1:9.2p1-2+deb12u3", "1:8.4p1-5+deb11u3"], 90, None),
    ("nginx", "Debian Nginx Maintainers <team@example.org>", 2, ["1.24.0-2ubuntu7.1", "1.22.1-9", "1.18.0-6.1+deb11u3"], 30, None),
    ("postgresql-16", "Debian PostgreSQL Maintainers <team@example.org>", 2, ["16.4-0ubuntu0.24.04.2", "16.2-1ubuntu4"], 10, None),
    ("postgresql-13", "Debian PostgreSQL Maintainers <team@example.org>", 2, ["13.16-0+deb11u1", "13.14-0+deb11u1"], 8, None),
    ("docker-ce", "Docker <docker@example.org>", 2, ["5:27.3.1-1~ubuntu.24.04~noble", "5:24.0.7-1~debian.11~bullseye"], 20, None),
    ("sudo", "Debian Sudo Maintainers <team@example.org>", 2, ["1.9.15p5-3ubuntu5", "1.9.5p2-3+deb11u1"], 99, None),
    ("xz-utils", "Debian XZ Maintainers <team@example.org>", 2, ["5.6.1+really5.4.5-1", "5.4.1-0.2", "5.2.5-2.1~deb11u1"], 99, None),
    ("base-files", "Debian Base <team@example.org>", 2, ["13ubuntu10.1", "12.4+deb12u7", "11.1+deb11u10"], 100, None),
]
VAPM_VERSIONS_VULNS = 8          # уязвимостей на каждую позицию версии от новейшей (новейшая — без уязвимостей)


def q(s: str) -> str:
    return "N'" + s.replace("'", "''") + "'"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=20000)
    ap.add_argument("--db", default="KAVBIG")
    a = ap.parse_args()
    H = a.hosts
    out: list[str] = [f"USE {a.db};", "SET NOCOUNT ON;"]
    out.append("""INSERT INTO dbo.v_akpub_adm_group VALUES (0, N'Управляемые устройства', 2, 0), (1, N'Нераспределенные устройства', NULL, 0), (10, N'Серверы', 0, 0),
 (11, N'Web', 10, 0), (12, N'Рабочие станции', 0, 0), (13, N'Филиал Север', 12, 0), (14, N'Филиал Юг', 12, 0), (15, N'Бухгалтерия', 12, 0);""")
    # компьютеры: каждый седьмой — сервер Linux; активность: 70% подключались за сутки, 15% — 1–30 сут, 15% — давно
    out.append(f""";WITH n AS (SELECT TOP ({H}) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b)
INSERT INTO dbo.v_akpub_host (nId, strName, wstrDisplayName, wstrDnsName, wstrDnsDomain, nIp, wstrOSName, nPlatformType, nVersionMajor, nVersionMinor, nOsBuildNumber, nGroup,
  tmLastNagentConnected, tmLastVisible, tmLastInfoUpdate, tmLastUpdate, tmLastFullScan, tmCreated, nStatus, nLastRtpState, bIsSlaveServer, nPkgMgrType, nComputerType, nProcType, nVirusCount, nUncured)
SELECT i + 100, 'g-' + CAST(i AS varchar(10)),
  CASE WHEN i % 7 = 0 THEN N'srv-' + RIGHT('00000' + CAST(i AS varchar(10)), 5) + N'.example.local' ELSE N'ws-' + RIGHT('00000' + CAST(i AS varchar(10)), 5) END,
  CASE WHEN i % 7 = 0 THEN N'srv-' ELSE N'ws-' END + RIGHT('00000' + CAST(i AS varchar(10)), 5), N'example.local', CAST(3323068416 AS bigint) + i,
  CASE WHEN i % 7 = 0 THEN CASE WHEN i % 3 = 0 THEN N'Linux' ELSE N'Ubuntu 24.04 LTS' END WHEN i % 11 = 0 THEN N'Microsoft Windows 10 Pro' ELSE N'Microsoft Windows 11 Pro' END,
  CASE WHEN i % 7 = 0 THEN 6 ELSE 2 END, CASE WHEN i % 7 = 0 THEN 6 ELSE 10 END, CASE WHEN i % 7 = 0 THEN 8 ELSE 0 END, CASE WHEN i % 7 = 0 THEN 0 ELSE 22631 END,
  CASE WHEN i % 7 = 0 THEN 10 + i % 2 WHEN i % 5 = 0 THEN 13 WHEN i % 5 = 1 THEN 14 WHEN i % 5 = 2 THEN 15 ELSE 12 END,
  CASE WHEN i % 20 < 14 THEN DATEADD(minute, -(i % 1440), GETUTCDATE()) WHEN i % 20 < 17 THEN DATEADD(day, -(1 + i % 29), GETUTCDATE()) WHEN i % 20 < 19 THEN DATEADD(day, -(31 + i % 300), GETUTCDATE()) ELSE NULL END,
  DATEADD(minute, -(i % 1440), GETUTCDATE()), DATEADD(minute, -(i % 1440), GETUTCDATE()), DATEADD(hour, -(i % 200), GETUTCDATE()), DATEADD(day, -(i % 60), GETUTCDATE()),
  DATEADD(day, -(100 + i % 900), GETUTCDATE()), 0, CASE WHEN i % 41 = 0 THEN 1 WHEN i % 97 = 0 THEN 9 ELSE 4 END, 0, CASE WHEN i % 7 = 0 THEN 2 ELSE 0 END, 1, 2,
  CASE WHEN i % 53 = 0 THEN 3 ELSE 0 END, CASE WHEN i % 151 = 0 THEN 1 ELSE 0 END
FROM n;""")
    # записи реестра
    prod_rows, fam_rows = [], []
    pid = 1000
    for fid, (name, pub, plat, vers, pop, vapm) in enumerate(FAMILIES, 1):
        fam_rows.append(f"({fid}, {plat}, {len(vers)}, {pop})")
        for vi, v in enumerate(vers):
            pid += 1
            nm = name.replace("{v}", v).replace("{v3}", ".".join(v.split(".")[:2]) + "." + str(int(v.split(".")[2]) // 1000) if "{v3}" in name else name.replace("{v}", v))
            if "{u}" in name:
                nm = name.replace("{u}", str(int(v.split(".")[2]) // 10))
            sid = f"{pid:032x}"
            prod_rows.append(f"({pid}, '{sid}', {q(nm)}, {q(v)}, {q(pub)}, {plat}, 0, DATEADD(day, -{30 * (vi + 1)}, GETUTCDATE()), {fid}, {vi})")
    out.append("CREATE TABLE #prod (nId bigint, strID char(32), name nvarchar(256), ver nvarchar(256), pub nvarchar(256), plat int, msi bit, first datetime, fid int, vidx int);")
    for k in range(0, len(prod_rows), 500):
        out.append("INSERT INTO #prod VALUES " + ",\n ".join(prod_rows[k:k + 500]) + ";")
    out.append("CREATE TABLE #fam (fid int, plat int, nver int, pop int);")
    out.append("INSERT INTO #fam VALUES " + ", ".join(fam_rows) + ";")
    out.append("""INSERT INTO dbo.hst_inventory_products (nId, strID, wstrDisplayName, wstrDisplayVersion, wstrPublisher, nPlatformTypeMask, bIsMsi, tmFirstAppear)
SELECT nId, strID, name, ver, pub, plat, msi, first FROM #prod;""")
    # прочие «автоматические» программы: 300 вымышленных названий Windows, по 2 версии
    out.append(""";WITH n AS (SELECT TOP (300) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects)
INSERT INTO dbo.hst_inventory_products (nId, strID, wstrDisplayName, wstrDisplayVersion, wstrPublisher, nPlatformTypeMask, bIsMsi, tmFirstAppear)
SELECT 50000 + i * 2 + v.k, RIGHT(REPLICATE('0', 32) + CAST(50000 + i * 2 + v.k AS varchar(20)), 32), N'Служебная программа ' + CAST(i AS nvarchar(10)) + N' ' + CAST(1 + v.k AS nvarchar(2)) + N'.' + CAST(i % 10 AS nvarchar(2)),
  CAST(1 + v.k AS nvarchar(2)) + N'.' + CAST(i % 10 AS nvarchar(2)) + N'.0', N'Example Software ' + CAST(i % 40 AS nvarchar(10)), 1, 1, DATEADD(day, -i, GETUTCDATE())
FROM n CROSS JOIN (VALUES (0), (1)) v(k);""")
    # установки семейств: компьютер получает семейство по псевдослучайному признаку, версия — по смещению (старые версии реже)
    out.append("""INSERT INTO dbo.hst_inventory_hstprds (nHostId, nProduct, tmInstallDate, bDeleted)
SELECT h.nId, p.nId, DATEADD(day, -((h.nId + p.nId) % 400), GETUTCDATE()), CASE WHEN (h.nId * 7 + p.nId) % 61 = 0 THEN 1 ELSE 0 END
FROM dbo.v_akpub_host h
JOIN #fam f ON f.plat = CASE WHEN h.nPlatformType = 6 THEN 2 ELSE 1 END AND (h.nId * 31 + f.fid * 17) % 100 < f.pop
JOIN #prod p ON p.fid = f.fid AND p.vidx = CASE WHEN (h.nId + f.fid * 13) % 10 < 5 THEN 0 ELSE (h.nId + f.fid) % f.nver END;""")
    out.append(""";WITH a AS (SELECT p.nId, ROW_NUMBER() OVER (ORDER BY p.nId) AS r FROM dbo.hst_inventory_products p WHERE p.nId >= 50000)
INSERT INTO dbo.hst_inventory_hstprds (nHostId, nProduct, tmInstallDate, bDeleted)
SELECT h.nId, a.nId, DATEADD(day, -((h.nId + a.nId) % 300), GETUTCDATE()), 0 FROM dbo.v_akpub_host h JOIN a ON (h.nId * 13 + a.r * 7) % 100 < 4 WHERE h.nPlatformType = 2;""")
    # уязвимости: на каждую не новейшую версию уязвимого семейства — vidx * VAPM_VERSIONS_VULNS описаний
    vapm = sorted({f[5] for f in FAMILIES if f[5]})
    out.append("CREATE TABLE #vp (vp_id bigint, name nvarchar(256));")
    out.append("INSERT INTO #vp VALUES " + ", ".join(f"({7000 + i}, {q(n)})" for i, n in enumerate(vapm, 1)) + ";")
    out.append("INSERT INTO dbo.v_vapm_product SELECT vp_id, name FROM #vp;")
    out.append("CREATE TABLE #famvp (fid int, vp_id bigint);")
    out.append("INSERT INTO #famvp VALUES " + ", ".join(f"({fid}, {7000 + vapm.index(f[5]) + 1})" for fid, f in enumerate(FAMILIES, 1) if f[5]) + ";")
    out.append("""INSERT INTO dbo.vapm_product_exact_version (nId, nProductId, strProductDisplVersion) SELECT p.nId + 100000, fv.vp_id, p.ver FROM #prod p JOIN #famvp fv ON fv.fid = p.fid WHERE p.vidx > 0;""")
    out.append(f""";WITH n AS (SELECT TOP (3000) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b)
INSERT INTO dbo.vapm_vulnerability_descr (nId, wstrPrimaryName, nKlSeverity, wstrDescriptionURL, bIgnore)
SELECT 100000 + i, N'KLA' + CAST(20000 + i AS nvarchar(10)), CASE WHEN i % 10 < 3 THEN 4 WHEN i % 10 < 7 THEN 2 ELSE 1 END,
  N'https://threats.kaspersky.com/en/vulnerability/KLA' + CAST(20000 + i AS nvarchar(10)), 0 FROM n;
;WITH n AS (SELECT TOP (3000) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b)
INSERT INTO dbo.vapm_vulnerability_names (nVulnerabilityDescrId, nSense, wstrName)
SELECT 100000 + i, 3, N'CVE-2024-' + CAST(10000 + i AS nvarchar(10)) FROM n UNION ALL SELECT 100000 + i, 3, N'CVE-2023-' + CAST(30000 + i AS nvarchar(10)) FROM n WHERE i % 4 = 0
UNION ALL SELECT 100000 + i, 6, CAST(5030000 + i AS nvarchar(10)) FROM n WHERE i % 5 = 0;
;WITH n AS (SELECT TOP (60) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS k FROM sys.all_objects)
INSERT INTO dbo.vapm_product_vulnerability (nId, nVulnerabilityDescrId, nProductExactVersionId, bIgnore)
SELECT ROW_NUMBER() OVER (ORDER BY p.nId, n.k) + 200000, 100000 + 1 + (p.nId * 37 + n.k * 101) % 3000, p.nId + 100000, 0
FROM #prod p JOIN #famvp fv ON fv.fid = p.fid JOIN n ON n.k <= p.vidx * {VAPM_VERSIONS_VULNS};
INSERT INTO dbo.vapm_vulnerability_occurence (nId, nHostId, nProductVulnerabilityId, nVulnerabilityDescrId, strSoftwareInventoryProductId, tmDetectTime, tmDisappearanceTime, bIgnore, bPatchesAvailable)
SELECT ROW_NUMBER() OVER (ORDER BY i.nId, pv.nId) + 300000, i.nHostId, pv.nId, NULL, p.strID, DATEADD(day, -((i.nHostId + pv.nId) % 200), GETUTCDATE()),
  CASE WHEN (i.nHostId + pv.nId) % 23 = 0 THEN GETUTCDATE() ELSE NULL END, 0, CASE WHEN pv.nId % 3 = 0 THEN 1 ELSE 0 END
FROM dbo.hst_inventory_hstprds i JOIN #prod p ON p.nId = i.nProduct JOIN dbo.vapm_product_vulnerability pv ON pv.nProductExactVersionId = p.nId + 100000 WHERE i.bDeleted = 0;""")
    # состояние защиты: Агент на всех, защитный продукт — кроме каждого 43-го; базы устарели у части; продукт остановлен у части
    out.append("""INSERT INTO dbo.v_akpub_hst_prdstate (nHost, wstrProductNameId, wstrProductVersionId, wstrProductDisplayName, wstrProductBuildNumber, nState, tmAvbasesDate, bAvProduct, bHasRtp)
SELECT h.nId, '1103', '1.0.0.0', N'Kaspersky Security Center Network Agent', CASE WHEN h.nId % 9 = 0 THEN '14.0.0.10902' WHEN h.nId % 4 = 0 THEN '14.2.0.26967' ELSE '15.1.0.20748' END, 3, NULL, 0, 0
FROM dbo.v_akpub_host h;
INSERT INTO dbo.v_akpub_hst_prdstate (nHost, wstrProductNameId, wstrProductVersionId, wstrProductDisplayName, wstrProductBuildNumber, nState, tmAvbasesDate, bAvProduct, bHasRtp)
SELECT h.nId, CASE WHEN h.nPlatformType = 6 THEN 'kesl' ELSE 'KES' END, CASE WHEN h.nPlatformType = 6 THEN '12.0.0.0' ELSE '11.0.0.0' END,
  CASE WHEN h.nPlatformType = 6 THEN N'Kaspersky Endpoint Security for Linux' ELSE N'Kaspersky Endpoint Security for Windows' END,
  CASE WHEN h.nPlatformType = 6 THEN CASE WHEN h.nId % 5 = 0 THEN '11.4.0.1096' ELSE '12.1.0.1297' END ELSE CASE WHEN h.nId % 6 = 0 THEN '11.11.0.452' WHEN h.nId % 3 = 0 THEN '12.4.0.467' ELSE '12.6.0.438' END END,
  CASE WHEN h.nId % 37 = 0 THEN 0 ELSE 3 END, DATEADD(hour, -CASE WHEN h.nId % 13 = 0 THEN 24 * (8 + h.nId % 40) ELSE h.nId % 30 END, GETUTCDATE()), 1, 1
FROM dbo.v_akpub_host h WHERE h.nId % 43 <> 0;
INSERT INTO dbo.v_akpub_host_status (nId, nStatus, nStatusMask)
SELECT h.nId, CASE WHEN h.nId % 43 = 0 OR h.nId % 37 = 0 THEN 1 WHEN h.nId % 13 = 0 OR h.nId % 17 = 0 THEN 2 ELSE 0 END,
  (CASE WHEN h.nId % 43 = 0 THEN 32 ELSE 0 END) | (CASE WHEN h.nId % 37 = 0 THEN 4 ELSE 0 END) | (CASE WHEN h.nId % 13 = 0 THEN 128 ELSE 0 END) | (CASE WHEN h.nId % 17 = 0 THEN 64 ELSE 0 END)
  | (CASE WHEN h.nId % 41 = 0 THEN 2 ELSE 0 END) | (CASE WHEN h.nId % 29 = 0 THEN 2048 ELSE 0 END) | (CASE WHEN h.nId % 59 = 0 THEN 512 ELSE 0 END)
FROM dbo.v_akpub_host h;""")
    # события за 90 суток: служебные, обнаружения, лечение, атаки
    out.append(f""";WITH n AS (SELECT TOP ({H * 15}) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b CROSS JOIN (SELECT TOP 20 1 AS x FROM sys.all_objects) c)
INSERT INTO dbo.v_akpub_ev_event (nId, nHostId, tmRiseTime, tmRegistrationTime, strEventType, wstrEventTypeDisplayName, nSeverity, wstrProductNameId, wstrDescription, wstrPar1, wstrPar2, wstrPar3, wstrPar4, wstrPar5, wstrPar7, wstrPar8)
SELECT i, 101 + (i * 7919) % {H}, DATEADD(minute, -(i % 129600), GETUTCDATE()), DATEADD(minute, -(i % 129600), GETUTCDATE()),
  CASE WHEN i % 100 < 85 THEN 'KLEVP_GroupTaskSyncState' WHEN i % 100 < 90 THEN 'GNRL_EV_VIRUS_FOUND' WHEN i % 100 < 93 THEN 'GNRL_EV_OBJECT_DELETED' WHEN i % 100 < 94 THEN 'GNRL_EV_OBJECT_NOTCURED'
       WHEN i % 100 < 95 THEN 'GNRL_EV_ATTACK_DETECTED' WHEN i % 100 < 97 THEN 'GNRL_EV_SUSPICIOUS_OBJECT_FOUND' ELSE 'KLSRV_HOST_STATUS_WARNING' END,
  CASE WHEN i % 100 < 85 THEN N'Синхронизация задачи' WHEN i % 100 < 90 THEN N'Обнаружен вредоносный объект' WHEN i % 100 < 93 THEN N'Объект удалён' WHEN i % 100 < 94 THEN N'Объект не вылечен'
       WHEN i % 100 < 95 THEN N'Обнаружена сетевая атака' WHEN i % 100 < 97 THEN N'Обнаружен подозрительный объект' ELSE N'Статус устройства изменён на «Предупреждение»' END,
  CASE WHEN i % 100 < 85 THEN 1 WHEN i % 100 < 90 THEN 4 WHEN i % 100 < 93 THEN 2 WHEN i % 100 < 94 THEN 3 WHEN i % 100 < 95 THEN 4 WHEN i % 100 < 97 THEN 3 ELSE 2 END,
  CASE WHEN i % 100 < 85 THEN N'1103' ELSE N'KES' END, N'Синтетическое событие',
  CASE WHEN i % 100 = 94 THEN CASE WHEN i % 3 = 0 THEN N'Scan.Generic.PortScan.TCP' ELSE N'Intrusion.Win.MS17-010.o' END ELSE NULL END,
  CASE WHEN i % 100 BETWEEN 85 AND 93 OR i % 100 IN (95, 96) THEN N'C:\\Users\\user\\Downloads\\file' + CAST(i % 500 AS nvarchar(10)) + N'.exe' WHEN i % 100 = 94 THEN N'TCP' ELSE NULL END,
  CASE WHEN i % 100 = 94 THEN CAST(CAST(3325256704 AS bigint) + i % 250 AS nvarchar(20)) ELSE NULL END,
  CASE WHEN i % 100 = 94 THEN N'445' ELSE NULL END,
  CASE WHEN i % 100 BETWEEN 85 AND 89 OR i % 100 IN (93, 95, 96) THEN CASE i % 6 WHEN 0 THEN N'HEUR:Trojan.Win32.Generic' WHEN 1 THEN N'EICAR-Test-File' WHEN 2 THEN N'not-a-virus:RiskTool.Win32.Example'
       WHEN 3 THEN N'Trojan-Downloader.Win32.Agent.gen' WHEN 4 THEN N'HEUR:Exploit.MSOffice.Generic' ELSE N'PDM:Trojan.Win32.Generic' END ELSE NULL END,
  CASE WHEN i % 100 BETWEEN 85 AND 89 THEN N'EXAMPLE\\user' + CAST(i % 300 AS nvarchar(10)) ELSE NULL END,
  CASE WHEN i % 100 BETWEEN 85 AND 89 THEN CASE i % 4 WHEN 0 THEN N'60' WHEN 1 THEN N'61' WHEN 2 THEN N'65' ELSE N'62' END ELSE NULL END
FROM n;""")
    out.append("DROP TABLE #prod; DROP TABLE #fam; DROP TABLE #vp; DROP TABLE #famvp;")
    print("\nGO\n".join(out) + "\nGO")


if __name__ == "__main__":
    main()
