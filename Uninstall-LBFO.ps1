<#  Uninstall-LBFO.ps1 — Fully uninstalls the LBFO provider to revert to "not enabled" state
    - Removes LBFO teams to maintain network connectivity (RDP-safe)
    - Stops and deletes the mslbfoprovider service
    - Deletes registry entries: Services, EventLog, Control\Network, Control\Class, DriverDatabase
    - Unregisters ms_lbfo via netcfg -u
    - Queues file deletions for next boot with unlock attempts
    - Optionally removes catalog files
    - Forces reboot to clear system state (with -AutoReboot)
    - Adds post-reboot validation to log and attempt residual file deletions
    - Logs to C:\ProgramData\LBFO\uninstall.log
    - Usage:
        .\Uninstall-LBFO.ps1
        .\Uninstall-LBFO.ps1 -AlsoRemoveCatalogs
        .\Uninstall-LBFO.ps1 -AutoReboot -AlsoRemoveCatalogs
#>

[CmdletBinding()]
param(
  [switch]$AlsoRemoveCatalogs,
  [switch]$AutoReboot
)

$ErrorActionPreference = 'Stop'

# -------- Constants -----------
$NetServiceClassGuid = '{4D36E974-E325-11CE-BFC1-08002BE10318}'
$InstanceGuid        = '{fc66a602-b769-4666-a540-ca3df0e7df2c}'
$ComponentId         = 'ms_lbfo'
$SvcName             = 'mslbfoprovider'
$InfNameDst          = 'MsLbfoProvider.inf'
$InfFolder           = 'mslbfoprovider.inf_amd64_f9d27a6b05ef21aa'
$CatGUID             = '{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'

# -------- Paths / Logging -----------
$ProgramDataDir = Join-Path $env:ProgramData 'LBFO'
$LogPath        = Join-Path $ProgramDataDir 'uninstall.log'

function Log([string]$msg, [ConsoleColor]$fg = [ConsoleColor]::Gray) {
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $line = "[$ts] $msg"
  Write-Host $line -ForegroundColor $fg
  Add-Content -Path $LogPath -Value $line -Force -ErrorAction SilentlyContinue
}

function Fatal([string]$msg) {
  Log "FATAL: $msg" Red
  throw $msg
}

function Ensure-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Fatal "Run this script in an elevated PowerShell (Run as Administrator)."
  }
}

function Queue-Delete([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) {
    Log "Path not found, skipping queue delete: $path" DarkCyan
    return
  }
  try {
    # Attempt to unlock file
    $file = [System.IO.File]::Open($path, 'Open', 'Read', 'None')
    $file.Close()
    $reg = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $name = 'PendingFileRenameOperations'
    $cur = (Get-ItemProperty -Path $reg -Name $name -ErrorAction SilentlyContinue).$name
    if ($null -eq $cur) { $cur = @() }
    if ($path -notmatch '^(\\\\\?\\|\\\?\\)') { $path = "\\??\$path" }
    $new = @($cur + $path, '')
    Set-ItemProperty -Path $reg -Name $name -Type MultiString -Value $new -Force
    Log "Queued for delete on next boot: $path" Green
  } catch {
    Log "Failed to queue delete for ${path}: $($_.Exception.Message)" Yellow
  }
}

# -------- Main --------
try {
  New-Item -ItemType Directory -Path $ProgramDataDir -Force | Out-Null
  "`n==== LBFO Uninstall log start $(Get-Date) ====`n" | Set-Content -Path $LogPath -Encoding UTF8
  Ensure-Admin

  # 1) Remove any LBFO teams
  Log "Removing LBFO teams if present" Cyan
  try { Import-Module NetLbfo -ErrorAction SilentlyContinue | Out-Null } catch { }
  $teams = @()
  try { $teams = Get-NetLbfoTeam -ErrorAction Stop } catch { }
  foreach ($t in $teams) {
    Log "Removing team: $($t.Name)" DarkCyan
    try {
      $members = @(Get-NetLbfoTeamMember -Team $t.Name -ErrorAction SilentlyContinue)
      foreach ($m in $members) {
        Remove-NetLbfoTeamMember -Team $t.Name -Name $m.Name -Confirm:$false -ErrorAction SilentlyContinue
        Log "Removed team member: $($m.Name) from $($t.Name)" DarkCyan
      }
      Remove-NetLbfoTeam -Name $t.Name -Confirm:$false -ErrorAction SilentlyContinue
      Log "Removed team: $($t.Name)" DarkCyan
    } catch {
      Log "Could not fully remove team $($t.Name): $($_.Exception.Message)" Yellow
    }
  }
  if ($teams.Count -eq 0) { Log "No LBFO teams found." DarkCyan }

  # 2) Unload NetLbfo module
  Log "Unloading NetLbfo module if loaded" Cyan
  try {
    Remove-Module NetLbfo -ErrorAction SilentlyContinue
    Log "Unloaded NetLbfo module" DarkCyan
  } catch {
    Log "Could not unload NetLbfo module: $($_.Exception.Message)" Yellow
  }

  # 3) Unregister ms_lbfo via netcfg
  Log "Unregistering ms_lbfo via netcfg" Cyan
  try {
    $out = (& netcfg.exe -u ms_lbfo) 2>&1
    Log "netcfg -u ms_lbfo output: $out" DarkCyan
  } catch {
    Log "netcfg -u ms_lbfo failed: $($_.Exception.Message)" Yellow
  }

  # 4) Stop and delete the provider service
  Log "Stopping and deleting mslbfoprovider service" Cyan
  try {
    Stop-Service -Name $SvcName -Force -ErrorAction SilentlyContinue
    Log "Stopped $SvcName service" DarkCyan
  } catch {
    Log "Could not stop $SvcName service: $($_.Exception.Message)" Yellow
  }
  try {
    & sc.exe delete $SvcName | Out-Null
    Log "Deleted $SvcName service" DarkCyan
  } catch {
    Log "Could not delete $SvcName service: $($_.Exception.Message)" Yellow
  }

  # 5) Unregister provider from Control\Network
  Log "Unregistering provider from Control\Network" Cyan
  $cnBase = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\$NetServiceClassGuid"
  $cnInst = Join-Path $cnBase $InstanceGuid
  if (Test-Path $cnInst) {
    Remove-Item $cnInst -Recurse -Force -ErrorAction SilentlyContinue
    Log "Removed $cnInst" DarkCyan
  } else {
    Log "No Control\Network instance key found: $cnInst" DarkCyan
  }
  # Broader cleanup for any ms_lbfo-related network entries
  try {
    Get-ChildItem $cnBase -ErrorAction SilentlyContinue |
      Where-Object { $_.PSChildName -match '^{.*}$' } |
      ForEach-Object {
        $p = $_.PSPath
        $cid = (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).ComponentId
        if ($cid -eq $ComponentId) {
          Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
          Log "Removed additional Control\Network entry: $p" DarkCyan
        }
      }
  } catch {
    Log "Control\Network additional cleanup failed: $($_.Exception.Message)" Yellow
  }

  # 6) Unregister provider from Control\Class
  Log "Unregistering provider from Control\Class" Cyan
  $ccBase = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$NetServiceClassGuid"
  if (Test-Path $ccBase) {
    Get-ChildItem $ccBase -ErrorAction SilentlyContinue |
      Where-Object { $_.PSChildName -match '^\d{4}$' } |
      ForEach-Object {
        $p = $_.PSPath
        $cid = (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).ComponentId
        $nci = (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).NetCfgInstanceId
        if ($cid -eq $ComponentId -or $nci -eq $InstanceGuid) {
          Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
          Log "Removed $p" DarkCyan
        }
      }
  } else {
    Log "NetService class key not found: $ccBase" DarkCyan
  }

  # 7) Remove EventLog entry
  Log "Removing EventLog entry" Cyan
  $eventLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System\$SvcName"
  if (Test-Path $eventLogPath) {
    Remove-Item $eventLogPath -Recurse -Force -ErrorAction SilentlyContinue
    Log "Removed $eventLogPath" DarkCyan
  } else {
    Log "No EventLog entry found: $eventLogPath" DarkCyan
  }

  # 8) Cleanup DRIVERS hive DriverDatabase
  Log "Cleaning DRIVERS hive DriverDatabase entries" Cyan
  $driversHiveLoaded = $false
  try {
    if (-not (Get-Item 'HKLM:\DRIVERS' -ErrorAction SilentlyContinue)) {
      reg.exe load HKLM\DRIVERS "$env:SystemRoot\System32\Config\DRIVERS" | Out-Null
      $driversHiveLoaded = $true
      Log "Loaded DRIVERS hive" DarkCyan
    }
  } catch {
    Log "Failed to load DRIVERS hive: $($_.Exception.Message)" Yellow
  }

  try {
    $dd = 'HKLM:\DRIVERS\DriverDatabase'
    $devIds = Join-Path $dd "DeviceIds\$ComponentId"
    if (Test-Path $devIds) {
      Remove-Item $devIds -Recurse -Force -ErrorAction SilentlyContinue
      Log "Removed $devIds" DarkCyan
    }

    $infFiles = Join-Path $dd 'DriverInfFiles\mslbfoprovider.inf'
    if (Test-Path $infFiles) {
      Remove-Item $infFiles -Recurse -Force -ErrorAction SilentlyContinue
      Log "Removed $infFiles" DarkCyan
    }

    $pkgRoot = Join-Path $dd 'DriverPackages'
    if (Test-Path $pkgRoot) {
      Get-ChildItem $pkgRoot -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like 'mslbfoprovider.inf_amd64_*' } |
        ForEach-Object {
          Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
          Log "Removed $($_.PSChildName)" DarkCyan
        }
    }
  } catch {
    Log "DRIVERS hive cleanup issue: $($_.Exception.Message)" Yellow
  } finally {
    if ($driversHiveLoaded) {
      try {
        reg.exe unload HKLM\DRIVERS | Out-Null
        Log "Unloaded DRIVERS hive" DarkCyan
      } catch {
        Log "Failed to unload DRIVERS hive: $($_.Exception.Message)" Yellow
      }
    }
  }

  # 9) Unregister any OEM INF
  Log "Queuing delete of any OEM INF that mentions mslbfoprovider" Cyan
  try {
    $infDir = Join-Path $env:SystemRoot 'INF'
    $oems = Get-ChildItem $infDir -Filter 'oem*.inf' -ErrorAction SilentlyContinue
    foreach ($f in $oems) {
      $hit = Select-String -Path $f.FullName -SimpleMatch 'mslbfoprovider' -ErrorAction SilentlyContinue
      if ($hit) {
        $base = [IO.Path]::GetFileNameWithoutExtension($f.Name)
        $pnf = Join-Path $f.DirectoryName ($base + '.pnf')
        Queue-Delete $f.FullName
        if (Test-Path $pnf) { Queue-Delete $pnf }
      }
    }
  } catch {
    Log "OEM INF scan failed: $($_.Exception.Message)" Yellow
  }

  # 10) Queue file removals
  Log "Queuing file removals for next boot" Cyan
  $filesToDelete = @(
    "$env:SystemRoot\System32\drivers\mslbfoprovider.sys",
    "$env:SystemRoot\System32\drivers\en-US\mslbfoprovider.sys.mui",
    "$env:SystemRoot\System32\DriverStore\en-US\MsLbfoProvider.inf_loc",
    "$env:SystemRoot\INF\MsLbfoProvider.inf"
  )
  foreach ($file in $filesToDelete) {
    Queue-Delete $file
  }

  $repo = Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository'
  Get-ChildItem $repo -Directory -Filter 'mslbfoprovider.inf_amd64_*' -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { Queue-Delete $_.FullName }
    Queue-Delete $_.FullName
  }

  # 11) Optionally queue catalog removals
  if ($AlsoRemoveCatalogs) {
    Log "Queuing catalog removals (optional)" Cyan
    $catRoot = Join-Path $env:SystemRoot "System32\CatRoot\$CatGUID"
    $patterns = @(
      'Microsoft-Windows-ServerCore-Drivers-merged-Package~31bf3856ad364e35~amd64~~10.0.20348.*.cat',
      'Microsoft-Windows-Server-Features-Package0*~31bf3856ad364e35~amd64~~10.0.20348.*.cat'
    )
    foreach ($pat in $patterns) {
      Get-ChildItem -Path (Join-Path $catRoot $pat) -ErrorAction SilentlyContinue | ForEach-Object {
        Queue-Delete $_.FullName
        Log "Queued catalog for deletion: $($_.FullName)" DarkCyan
      }
    }
    Log "Note: Removing catalogs is optional. Leaving them is harmless." DarkCyan
  }

  # 12) Set RunOnce for post-reboot validation and cleanup
  Log "Setting RunOnce for post-reboot validation and cleanup" Cyan
  $validationScript = Join-Path $ProgramDataDir 'validate_uninstall.ps1'
  $validationContent = @"
`$logPath = '$LogPath'
function Log([string]`$msg, [ConsoleColor]`$fg = [ConsoleColor]::Gray) {
  `$ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  `$line = "[`$ts] `$msg"
  Write-Host `$line -ForegroundColor `$fg
  Add-Content -Path `$logPath -Value `$line -Force -ErrorAction SilentlyContinue
}
Log "Post-reboot validation started" Cyan
`$files = @(
  '$env:SystemRoot\System32\drivers\mslbfoprovider.sys',
  '$env:SystemRoot\System32\drivers\en-US\mslbfoprovider.sys.mui',
  '$env:SystemRoot\System32\DriverStore\en-US\MsLbfoProvider.inf_loc',
  '$env:SystemRoot\INF\MsLbfoProvider.inf'
)
foreach (`$file in `$files) {
  if (Test-Path `$file) {
    Log "Residual file found: `$file" Red
    try {
      `$f = [System.IO.File]::Open(`$file, 'Open', 'Read', 'None')
      `$f.Close()
      Remove-Item `$file -Force -ErrorAction Stop
      Log "Deleted residual file: `$file" Green
    } catch {
      Log "Failed to delete residual file `$file: `$(`$_.Exception.Message)" Yellow
    }
  } else {
    Log "File successfully removed: `$file" Green
  }
}
`$repo = '$repo'
if (Test-Path (Join-Path `$repo 'mslbfoprovider.inf_amd64_*')) {
  Log "Residual DriverStore repository found: `$repo\mslbfoprovider.inf_amd64_*" Red
  try {
    Remove-Item (Join-Path `$repo 'mslbfoprovider.inf_amd64_*') -Recurse -Force -ErrorAction Stop
    Log "Deleted residual DriverStore repository" Green
  } catch {
    Log "Failed to delete residual DriverStore repository: `$(`$_.Exception.Message)" Yellow
  }
} else {
  Log "DriverStore repository successfully removed" Green
}
try {
  `$out = (& netcfg.exe -s s) 2>&1
  if (`$out -match 'ms_lbfo') {
    Log "Residual ms_lbfo found in netcfg -s s: `$out" Red
    try {
      & netcfg.exe -u ms_lbfo | Out-Null
      Log "Unregistered residual ms_lbfo via netcfg" Green
    } catch {
      Log "Failed to unregister residual ms_lbfo: `$(`$_.Exception.Message)" Yellow
    }
  } else {
    Log "No ms_lbfo found in netcfg -s s" Green
  }
} catch {
  Log "netcfg -s s failed: `$(`$_.Exception.Message)" Yellow
}
try {
  `$out = (& sc.exe query $SvcName) 2>&1
  Log "sc query $SvcName output: `$out" DarkCyan
} catch {
  Log "sc query $SvcName failed: `$(`$_.Exception.Message)" Yellow
}
try {
  `$out = New-NetLbfoTeam -Name 'Team0' -TeamNicName 'Team0' -TeamMembers 'Ethernet' -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Verbose -ErrorAction Stop
  Log "Unexpected: New-NetLbfoTeam succeeded: `$out" Red
} catch {
  if (`$_.Exception.Message -match 'The LBFO feature is not currently enabled') {
    Log "New-NetLbfoTeam failed as expected: `$(`$_.Exception.Message)" Green
  } else {
    Log "New-NetLbfoTeam failed unexpectedly: `$(`$_.Exception.Message)" Red
  }
}
Log "Post-reboot validation complete" Cyan
"@
  $validationContent | Out-File -FilePath $validationScript -Encoding UTF8
  $runOnceCmd = "powershell.exe -ExecutionPolicy Bypass -File `"$validationScript`""
  try {
    reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "LBFO-Validate" /t REG_SZ /d "$runOnceCmd" /f | Out-Null
    Log "Set RunOnce for post-reboot validation: $validationScript" DarkCyan
  } catch {
    Log "Failed to set RunOnce for validation: $($_.Exception.Message)" Yellow
  }

  # 13) Finalize
  Log "Finalizing uninstall" Cyan
  try {
    & sc.exe config $SvcName start= disabled | Out-Null
    Log "Set $SvcName service to disabled" DarkCyan
  } catch {
    Log "Could not set $SvcName service to disabled (likely already deleted): $($_.Exception.Message)" DarkCyan
  }

  Log "Uninstall complete. Reboot to finalize file deletions and clear system state." Green
  Log "After reboot, New-NetLbfoTeam should fail with 'The LBFO feature is not currently enabled, or LBFO is not supported on this SKU.'" Green
  Log "Post-reboot validation will log to $LogPath" Green

  if ($AutoReboot) {
    Log "Rebooting in 10 seconds to complete uninstall (Ctrl+C to cancel)..." Yellow
    Start-Sleep -Seconds 10
    Start-Process "shutdown.exe" -ArgumentList "/r /t 0" -WindowStyle Hidden
  }
}
catch {
  Log "Uninstall failed: $($_.Exception.Message)" Red
  throw $_
}