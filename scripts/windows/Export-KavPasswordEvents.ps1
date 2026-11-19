<#
.SYNOPSIS
  Выгрузка событий смены (4723) и сброса (4724) пароля из журналов Security контроллеров домена для раздела «Аудит домена» KAV Checker.

.DESCRIPTION
  Только чтение. Ничего не меняет в домене и на контроллерах. Для каждого контроллера выгружает:
    * события 4723 (пользователь меняет свой пароль) и 4724 (пароль сбрасывает другая учётная запись) — успешные и неуспешные;
    * охват журнала Security: время первого и последнего сохранённого события (без этого отсутствие события нельзя отличить от отсутствия данных).
  Пароли и иные секреты в событиях не содержатся и в файл не попадают.

  Минимальные права: учётная запись, от имени которой запускается скрипт, — член встроенной группы домена «Event Log Readers»
  (Builtin\Event Log Readers, действует на всех контроллерах). Права администратора домена не нужны.
  На контроллерах должно быть разрешено правило брандмауэра «Удалённое управление журналом событий» (RPC) и включён аудит
  «Аудит управления учётными записями пользователей» (Audit User Account Management: Success, Failure).

.PARAMETER Days
  Глубина выгрузки в сутках (по умолчанию 400). Журнал хранит столько, сколько позволяет его размер: фактический охват пишется в файл.

.PARAMETER DomainControllers
  Список контроллеров. По умолчанию — все контроллеры текущего домена.

.PARAMETER OutFile
  Файл результата (JSON, UTF-8). Загрузите его в KAV Checker: «Аудит домена → Сброс пароля → Загрузить журналы».

.EXAMPLE
  .\Export-KavPasswordEvents.ps1 -Days 120 -OutFile C:\Temp\pwd-events.json
#>
[CmdletBinding()]
param(
    [int]$Days = 400,
    [string[]]$DomainControllers,
    [string]$OutFile = ".\kav-pwd-events.json"
)
$ErrorActionPreference = 'Stop'

if (-not $DomainControllers) {
    $DomainControllers = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | ForEach-Object { $_.Name }
}
$since = (Get-Date).AddDays(-$Days)
$auditSuccess = [int64]0x0020000000000000
$dcs = @(); $events = New-Object System.Collections.Generic.List[object]

foreach ($dc in $DomainControllers) {
    $info = [ordered]@{ name = $dc; log_from = $null; log_to = $null; error = "" }
    try {
        $old = Get-WinEvent -ComputerName $dc -LogName Security -MaxEvents 1 -Oldest
        $new = Get-WinEvent -ComputerName $dc -LogName Security -MaxEvents 1
        $from = $old.TimeCreated
        if ($from -lt $since) { $from = $since }
        $info.log_from = $from.ToUniversalTime().ToString("o")
        $info.log_to = $new.TimeCreated.ToUniversalTime().ToString("o")
        $found = Get-WinEvent -ComputerName $dc -FilterHashtable @{ LogName = 'Security'; Id = 4723, 4724; StartTime = $since } -ErrorAction SilentlyContinue
        foreach ($e in $found) {
            $d = @{}
            foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            $events.Add([ordered]@{
                dc = $dc; record_id = $e.RecordId; id = $e.Id; time_utc = $e.TimeCreated.ToUniversalTime().ToString("o")
                success = (([int64]$e.Keywords -band $auditSuccess) -ne 0)
                target_user = $d['TargetUserName']; target_domain = $d['TargetDomainName']; target_sid = $d['TargetSid']
                subject_user = $d['SubjectUserName']; subject_domain = $d['SubjectDomainName']; subject_sid = $d['SubjectUserSid']
            })
        }
        Write-Host ("{0}: событий {1}, журнал с {2:dd.MM.yyyy}" -f $dc, @($found).Count, $from)
    } catch {
        $info.error = $_.Exception.Message
        Write-Warning ("{0}: {1}" -f $dc, $_.Exception.Message)
    }
    $dcs += $info
}

$doc = [ordered]@{ format = "kavcheck-pwd-events/1"; generated_at = (Get-Date).ToUniversalTime().ToString("o"); days = $Days; dcs = $dcs; events = $events }
$path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)      # абсолютный или относительный путь
[System.IO.File]::WriteAllText($path, ($doc | ConvertTo-Json -Depth 4 -Compress), (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("Готово: {0} событий, контроллеров {1}. Файл: {2}" -f $events.Count, $dcs.Count, $OutFile)
