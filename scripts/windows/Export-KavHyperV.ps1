<#
.SYNOPSIS
  Выгрузка сведений Hyper-V для KAV Checker (раздел «Инвентаризация → Инфраструктура», источник «Hyper-V»). Только чтение.

.DESCRIPTION
  Собирает с указанных хостов Hyper-V: хосты (имя, FQDN, серийный номер, SMBIOS UUID, CPU, ОЗУ, кластер) и виртуальные машины
  (идентификатор, имя, состояние, CPU, память, диски, MAC и IP-адреса, BIOSGUID — идентификатор, который видит гостевая ОС).
  Ничего не меняет. Права: членство в группе «Hyper-V Administrators» на хостах (или локальный администратор) — только для чтения сведений;
  для удалённых хостов нужен доступ WinRM/CIM. Результат — JSON (format kavcheck-hyperv/1), загружается в KAV Checker кнопкой «Загрузить выгрузку».

.EXAMPLE
  .\Export-KavHyperV.ps1 -ComputerName hv01, hv02 -OutFile hyperv.json
#>
[CmdletBinding()]
param(
  [string[]] $ComputerName = @($env:COMPUTERNAME),
  [string] $OutFile = "hyperv.json"
)
$ErrorActionPreference = "Stop"
$hosts = @(); $vms = @()
foreach ($h in $ComputerName) {
  try {
    $cs = Get-CimInstance -ComputerName $h -ClassName Win32_ComputerSystem
    $prod = Get-CimInstance -ComputerName $h -ClassName Win32_ComputerSystemProduct
    $bios = Get-CimInstance -ComputerName $h -ClassName Win32_BIOS
    $cluster = ""
    try { $cluster = (Get-CimInstance -ComputerName $h -Namespace root/MSCluster -ClassName MSCluster_Cluster -ErrorAction Stop).Name } catch { }
    $hosts += [ordered]@{ name = $cs.Name; fqdn = "$($cs.Name).$($cs.Domain)"; serial = $bios.SerialNumber; uuid = $prod.UUID;
                          cpu = $cs.NumberOfLogicalProcessors; ram_mb = [int]($cs.TotalPhysicalMemory / 1MB); cluster = $cluster }
    $settings = @{}
    Get-CimInstance -ComputerName $h -Namespace root/virtualization/v2 -ClassName Msvm_VirtualSystemSettingData |
      Where-Object { $_.VirtualSystemType -eq "Microsoft:Hyper-V:System:Realized" } | ForEach-Object { $settings[$_.VirtualSystemIdentifier.ToLower()] = $_.BIOSGUID }
    foreach ($vm in Get-VM -ComputerName $h) {
      $nics = Get-VMNetworkAdapter -VM $vm
      $disk = 0
      foreach ($d in Get-VMHardDiskDrive -VM $vm) { try { $disk += (Get-VHD -ComputerName $h -Path $d.Path).Size } catch { } }
      $vms += [ordered]@{ id = "$($vm.VMId)"; name = $vm.Name; host = $cs.Name; state = "$($vm.State)"; cpu = $vm.ProcessorCount;
                          ram_mb = [int]($vm.MemoryStartup / 1MB); disk_gb = [math]::Round($disk / 1GB, 1);
                          macs = @($nics | ForEach-Object { $_.MacAddress }); ips = @($nics | ForEach-Object { $_.IPAddresses } | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' });
                          bios_guid = "$($settings["$($vm.VMId)".ToLower()])" }
    }
  } catch {
    Write-Warning "Хост ${h}: $($_.Exception.Message)"
  }
}
$doc = [ordered]@{ format = "kavcheck-hyperv/1"; generated_at = (Get-Date).ToUniversalTime().ToString("o"); hosts = $hosts; vms = $vms }
$doc | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutFile -Encoding utf8
Write-Host "Готово: $OutFile (хостов: $($hosts.Count), ВМ: $($vms.Count))"
