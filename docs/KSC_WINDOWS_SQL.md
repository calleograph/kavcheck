# Подготовка SQL Server на Windows-сервере KSC для KAV Checker

Для администратора Kaspersky Security Center, у которого Сервер администрирования и SQL Server (обычно Express) стоят на одном Windows-сервере, а KAV Checker работает на другом. Здесь — как выдать KAV Checker доступ **только на чтение** и не нарушить штатную работу самого KSC.

Адреса в примерах условные: `192.0.2.10` — SQL Server (он же Сервер администрирования), `192.0.2.50` — сервер KAV Checker, `kavcheck_ro` — учётная запись для чтения.

## Главное правило

С одной базой KSC (`KAV`) работают **два независимых подключения**. Не смешивайте их:

| | Служба KSC (`klserver`) | KAV Checker |
|---|---|---|
| Учётная запись | локальная `KL-AK-*` | SQL-логин `kavcheck_ro` |
| Аутентификация | Windows | SQL Server |
| Роль в базе `KAV` | `db_owner` (так устроен KSC) | только `db_datareader` |
| Подключение | локальное, старым 32-разрядным клиентом (SQLOLEDB) | удалённое, TCP с ограничением по IP |

Всё, что вы меняете для KAV Checker (TCP/IP, порт, сетевой экран, режим аутентификации), **затрагивает и SQL-клиент KSC**. На практике после таких правок KSC терял связь с базой: сетевой экран пропускал только адрес KAV Checker, а старый клиент KSC не мог разрешить имя `.\SQLEXPRESS`. Поэтому после **каждого** шага проверяйте штатное подключение KSC (шаг 0 и шаг 6). Если проверка перестала проходить — остановитесь и верните прежнее состояние (раздел «Откат»).

KAV Checker сам ничего на Windows-сервере не меняет и базу KSC не изменяет: он только читает.

## Шаг 0. Снимите исходное состояние (ничего не меняется)

Выполните в PowerShell от администратора и сохраните вывод: он пригодится для отката.

```powershell
# службы и учётные записи
Get-CimInstance Win32_Service | Where-Object Name -match 'MSSQL|SQLBrowser|kladminserver' |
  Format-Table Name,State,StartName,ProcessId

# экземпляры SQL Server
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'

# кто слушает порты
Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 1433,1434,13291 |
  Format-Table LocalAddress,LocalPort,OwningProcess

# как KSC подключается к базе (только чтение настроек)
$d='C:\Program Files (x86)\Kaspersky Lab\Kaspersky Security Center'
& "$d\klscflag.exe" -ssvget -pv klserver -s 87 -n KLSRV_CONNECTION_DATA -svt PARAMS_T -ss '|ss_type = "SS_SETTINGS";'
```

Что записать: имя экземпляра (`SQLEXPRESS`, `SQLEXPRESS01`…), имя базы (`KLDBCON_DB`), исходное имя сервера (`KLDBCON_HOST`, обычно `.\ИМЯ_ЭКЗЕМПЛЯРА`), на каком адресе и порту слушает SQL Server, правила сетевого экрана для порта SQL, есть ли клиентские алиасы:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\MSSQLServer\Client\ConnectTo' -ErrorAction SilentlyContinue   # 32-разрядные клиенты (KSC)
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo' -ErrorAction SilentlyContinue               # 64-разрядные
```

**Контрольная точка.** Проверьте подключение тем же клиентом, что у KSC (32-разрядный SQLOLEDB), — `sqlcmd -E` для этого недостаточно, он использует другой клиент. Имя в `Data Source` — то, что вы записали в `KLDBCON_HOST`.

```powershell
$f="$env:TEMP\ksc-sql-test.vbs"
@('On Error Resume Next',
  'Set c=CreateObject("ADODB.Connection")',
  'c.ConnectionTimeout=5',
  'c.Open "Provider=SQLOLEDB;Data Source=.\SQLEXPRESS;Initial Catalog=KAV;Integrated Security=SSPI;"',
  'If Err.Number = 0 Then',
  'WScript.Echo "SUCCESS"',
  'c.Close',
  'Else',
  'WScript.Echo "FAIL: " & Hex(Err.Number) & " " & Err.Description',
  'End If') | Set-Content $f -Encoding ASCII
& "$env:windir\SysWOW64\cscript.exe" //nologo $f      # именно 32-разрядный cscript
Remove-Item $f -Force
```

Должно быть `SUCCESS`. Тест идёт под вашей учётной записью, а не под учётной записью службы KSC; полная проверка — консоль KSC (шаг 6). Если `FAIL` уже сейчас — это не из-за KAV Checker; разберитесь с этим до всех остальных шагов.

## Шаг 1. Режим аутентификации SQL Server

KAV Checker подключается SQL-логином, а для этого нужен смешанный режим.

```sql
SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsOnlyAuth;   -- 1 — только Windows, 0 — смешанный
```

Если `1`: SQL Server Management Studio → свойства сервера → Security → «SQL Server and Windows Authentication mode» → ОК → **перезапуск службы этого экземпляра SQL Server**. Перезапуск ненадолго прерывает работу KSC и других приложений на этом экземпляре — согласуйте окно работ. После запуска проверьте значение ещё раз (должно быть `0`).

> Подводный камень: при `1` логин и пароль могут быть созданы правильно, а вход всё равно отклоняется — с тем же сообщением «Login failed», что и при неверном пароле. Если вход не проходит при верном пароле, проверьте режим первым делом.

## Шаг 2. Логин и пользователь только на чтение

Отдельный логин на **каждый** Сервер администрирования, пароль уникальный и длинный.

```sql
USE master;
CREATE LOGIN [kavcheck_ro] WITH PASSWORD = N'<уникальный пароль>', CHECK_POLICY = ON, CHECK_EXPIRATION = OFF;
GO
USE KAV;
CREATE USER [kavcheck_ro] FOR LOGIN [kavcheck_ro] WITH DEFAULT_SCHEMA = dbo;
ALTER ROLE db_datareader ADD MEMBER [kavcheck_ro];
GO
```

Логин на уровне сервера и пользователь в базе — разные объекты: без `CREATE USER` в `KAV` вход пройдёт, а чтение — нет. Если объекты уже есть, не создавайте их повторно, а проверьте:

```sql
SELECT name, is_disabled FROM sys.server_principals WHERE name = N'kavcheck_ro';
USE KAV;
SELECT dp.name, r.name AS role FROM sys.database_principals dp
LEFT JOIN sys.database_role_members m ON m.member_principal_id = dp.principal_id
LEFT JOIN sys.database_principals r ON r.principal_id = m.role_principal_id
WHERE dp.name = N'kavcheck_ro';
```

Нужна одна роль — `db_datareader`. Не выдавайте `db_owner`, `db_datawriter`, `db_ddladmin`, `sysadmin`, `securityadmin`. Роль и учётную запись службы KSC не трогайте. Диагностика KAV Checker предупредит, если у логина есть права на запись.

## Шаг 3. TCP/IP и постоянный порт

Именованный экземпляр SQL Express по умолчанию слушает **динамический** порт, который может смениться после перезапуска. Задайте постоянный (SQL Server Configuration Manager → Протоколы для экземпляра → TCP/IP):

1. Включите TCP/IP.
2. Вкладка «IP-адреса»: для нужного адреса (или `IPAll`) укажите «TCP-порт» = `1433`, «Динамические TCP-порты» — **пусто**. Если `ListenOnAllIPs = Нет`, настраивается конкретный адрес; не включайте прослушивание на всех интерфейсах без необходимости.
3. Если на сервере несколько экземпляров — порты разные. Порт должен быть свободен.
4. Перезапустите только этот экземпляр SQL Server.

Протоколы Shared Memory и Named Pipes **оставьте как были**: ими может пользоваться KSC.

SQL Server Browser (UDP 1434) нужен только при подключении по имени экземпляра. KAV Checker подключается по адресу и порту (`192.0.2.10:1433`), поэтому Browser ему не нужен; состояние службы не меняйте — им могут пользоваться другие программы.

## Шаг 4. Windows Firewall

Откройте входящий TCP 1433 **только для адреса KAV Checker**:

```powershell
New-NetFirewallRule -DisplayName 'KAV Checker: SQL read' -Direction Inbound -Protocol TCP -LocalPort 1433 `
  -RemoteAddress '192.0.2.50' -Action Allow -Profile Domain
```

Сначала посмотрите существующие правила для этого порта (`Get-NetFirewallRule | Get-NetFirewallPortFilter`), чтобы не создавать дубли, и убедитесь, что профиль правила совпадает с профилем сети (`Get-NetConnectionProfile`).

**Особый случай — KSC ходит в SQL по TCP через собственный адрес сервера.** Если после этого шага шаг 6 падает, а при временно добавленном собственном адресе сервера (`192.0.2.10`) в `-RemoteAddress` проходит, значит, локальный KSC подключается к SQL Server по TCP через свой сетевой интерфейс, и ограничение «только адрес KAV Checker» отрезало его. Добавьте в то же правило **только** собственный адрес сервера:

```powershell
Set-NetFirewallRule -DisplayName 'KAV Checker: SQL read' -RemoteAddress '192.0.2.50','192.0.2.10'
```

Не добавляйте `0.0.0.0/0`, широкие подсети и все адреса сервера. `::1` в `-RemoteAddress` не принимается (ошибка), loopback этим правилом не открывается.

## Шаг 5. Шифрование (TLS)

В KAV Checker по умолчанию шифрование «обязательно» и «доверять сертификату сервера» включено — этого достаточно для самоподписанного сертификата SQL Server.

Для проверки сертификата (рекомендуется в промышленной среде) нужен сертификат с назначением «Проверка подлинности сервера», закрытым ключом, доступным учётной записи службы SQL Server, именами в SAN, по которым подключается KAV Checker, и корневым сертификатом ЦС, которому доверяет сервер KAV Checker. Не включайте «Force Encryption» на всём экземпляре без согласования: это затронет другие приложения и старый клиент KSC.

## Шаг 6. Проверка, что KSC продолжает работать

Повторите контрольную точку шага 0 (32-разрядный `cscript`, тот же `Data Source`), затем проверьте саму службу и консоль:

- служба `kladminserver` запущена, слушает порт 13291 (это порт Сервера администрирования, не SQL);
- консоль KSC подключается и проходит инициализацию (она может занять несколько минут после перезапуска службы);
- в журнале событий Windows нет новых ошибок подключения к базе.

Если `FAIL` — перейдите к шагу 7. Если консоль не открывается — откатите последнее изменение.

## Шаг 7. Клиентский алиас для KSC (только если проверка шага 6 не проходит)

Если старый клиент KSC после правок не разрешает привычное имя экземпляра (`.\SQLEXPRESS`), создайте клиентский алиас, который переводит это имя в адрес и порт. Это настройка клиента на этом компьютере, а не SQL Server, и нужна она **только при подтверждённой проблеме** (проверкой 32-разрядным SQLOLEDB).

Предпочтительный способ — утилита сетевого клиента SQL Server для 32-разрядных приложений:

```powershell
& "$env:windir\SysWOW64\cliconfg.exe"      # вкладка «Псевдоним» → Добавить: имя .\SQLEXPRESS, TCP/IP, сервер 192.0.2.10, порт 1433
```

Либо через реестр (то же самое; ветка `WOW6432Node` — для 32-разрядного KSC). Сначала сохраните ветку:

```powershell
$k='HKLM\SOFTWARE\WOW6432Node\Microsoft\MSSQLServer\Client\ConnectTo'
reg export "HKLM\SOFTWARE\WOW6432Node\Microsoft\MSSQLServer\Client" "$env:USERPROFILE\sql-client-before.reg" /y
reg add "$k" /v ".\SQLEXPRESS" /t REG_SZ /d "DBMSSOCN,192.0.2.10,1433" /f
```

Имя в `/v` — ровно то, что записано в `KLDBCON_HOST`; значение — `DBMSSOCN,<адрес SQL Server>,<порт>`. Алиас в 64-разрядной ветке (`HKLM\SOFTWARE\Microsoft\...`) — другая настройка и 32-разрядный KSC её не использует. Затем повторите проверку шага 0; при необходимости перезапустите `kladminserver` и дождитесь инициализации консоли. Не меняйте через `klscflag` параметры подключения KSC к базе.

## Шаг 8. Проверка из KAV Checker

С сервера KAV Checker:

```bash
nc -vz 192.0.2.10 1433            # порт доступен (это только TCP, не вход)
```

Затем «Администрирование → Источники KSC → Добавить источник»: SQL Server `192.0.2.10`, порт `1433`, база `KAV`, SQL Server-авторизация, `kavcheck_ro`, «Сохранить и проверить». Диагностика показывает этапы отдельно — по этапу видно, что не так:

| Этап не прошёл | Вероятная причина |
|---|---|
| соединение: тайм-аут | порт закрыт на сетевом экране (адрес KAV Checker не в правиле), SQL Server не слушает этот адрес и порт, неверный порт |
| соединение: отказ, имя не найдено | неверный адрес, TCP/IP выключен, динамический порт вместо `1433` |
| вход отклонён | неверный пароль; логин отключён; **SQL Server работает только в режиме Windows** (шаг 1) |
| база недоступна | неверное имя базы; нет пользователя в `KAV` (шаг 2) |
| шифрование | режим шифрования; сертификат сервера (шаг 5) |
| объекты KSC | другая версия KSC; нет прав чтения |
| роли | у логина есть лишние права — уберите, оставьте `db_datareader` |

## Откат

Только то, что создали вы, в таком порядке:

1. Правило сетевого экрана: `Remove-NetFirewallRule -DisplayName 'KAV Checker: SQL read'` (если до этого порт был закрыт; иначе верните прежние правила из шага 0).
2. Алиас: `reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\MSSQLServer\Client\ConnectTo" /v ".\SQLEXPRESS" /f` — только если создавали его, или `reg import` сохранённого файла.
3. Порт и протоколы: верните прежние значения из шага 0 и перезапустите экземпляр.
4. Режим аутентификации: верните «Windows Authentication» только по согласованному плану (перезапуск экземпляра).
5. Учётная запись: `ALTER ROLE db_datareader DROP MEMBER [kavcheck_ro];` → `USE KAV; DROP USER [kavcheck_ro];` → `USE master; DROP LOGIN [kavcheck_ro];`.
6. Проверьте шаг 6: 32-разрядный SQLOLEDB, служба, консоль.

## Чего не делать

- Не использовать учётную запись службы KSC (`KL-AK-*`) для KAV Checker и не давать KAV Checker `db_owner`.
- Не менять владельца базы, схему `dbo`, параметры базы, права службы KSC, подключение KSC к базе.
- Не проверять работоспособность KSC только `sqlcmd`: он использует другой клиент.
- Не открывать порт SQL Server всем адресам и не отключать сетевой экран.
- Не делать нагрузочные проверки и массовые запросы на рабочем SQL Server — только чтение, как делает KAV Checker.

## Официальная документация

- [Kaspersky Security Center: учётные записи для работы с СУБД](https://support.kaspersky.com/KSC/14/en-US/156275.htm)
- [Microsoft: свойства TCP/IP (вкладка IP-адреса)](https://learn.microsoft.com/en-us/sql/tools/configuration-manager/tcp-ip-properties-ip-addresses-tab)
- [Microsoft: SQL Server Browser](https://learn.microsoft.com/en-us/sql/tools/configuration-manager/sql-server-browser-service)
- [Microsoft: Windows Firewall для SQL Server](https://learn.microsoft.com/en-us/sql/sql-server/install/configure-the-windows-firewall-to-allow-sql-server-access)
- [Microsoft: алиасы клиента (ConnectTo)](https://learn.microsoft.com/en-us/windows/win32/devnotes/connectto)
- [Microsoft: роли уровня базы данных](https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/database-level-roles)
- [Microsoft: требования к сертификатам SQL Server](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/certificate-requirements)
