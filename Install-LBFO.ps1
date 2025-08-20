[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# -------- INF constants -----------
$ClassGuidNS  = '{4D36E974-E325-11CE-BFC1-08002BE10318}'   # NetService
$InstanceGuid = '{fc66a602-b769-4666-a540-ca3df0e7df2c}'    # NetCfgInstanceId in [Install]
$ComponentId  = 'ms_lbfo'
$SvcName      = 'mslbfoprovider'
$InfNameDst   = 'MsLbfoProvider.inf'  # Match registry InfPath
$InfFolder    = 'mslbfoprovider.inf_amd64_f9d27a6b05ef21aa'
$CatGUID      = '{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
$ImageIndex   = '4'

# -------- paths / logging ----------
$ProgramDataDir = Join-Path $env:ProgramData 'LBFO'
$CfgPath        = Join-Path $ProgramDataDir 'cfg.json'
$LogPath        = Join-Path $ProgramDataDir 'install.log'

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
  $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object System.Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fatal "Run this from an elevated PowerShell (Run as Administrator)."
  }
}

function Ensure-System {
  $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  Log "Current security context: $identity" Cyan
  if ($identity -eq 'NT AUTHORITY\SYSTEM') { return }

  Ensure-Admin
  $psexec = Join-Path $PSScriptRoot 'PsExec.exe'
  if (-not (Test-Path $psexec)) {
    Fatal "PsExec.exe not found at: $psexec. Place PsExec.exe beside Install-LBFO.ps1 and run again."
  }
  Log "Re-launching under SYSTEM via PsExec..." Yellow
  $args = @(
    '-accepteula', '-s', '-i', '-h',
    'powershell.exe', '-ExecutionPolicy', 'Bypass', '-NoProfile',
    '-File', "`"$PSCommandPath`""
  )
  try {
    $p = Start-Process -FilePath $psexec -ArgumentList $args -PassThru -Wait -RedirectStandardError "$ProgramDataDir\psexec_err.log" -RedirectStandardOutput "$ProgramDataDir\psexec_out.log" -WindowStyle Hidden -ErrorAction Stop
    Log "PsExec exit code: $($p.ExitCode)" DarkCyan
    if ($p.ExitCode -ne 0) {
      $err = Get-Content -Path "$ProgramDataDir\psexec_err.log" -ErrorAction SilentlyContinue
      $out = Get-Content -Path "$ProgramDataDir\psexec_out.log" -ErrorAction SilentlyContinue
      Log "PsExec error output: $err" Red
      Log "PsExec output: $out" DarkCyan
      Fatal "PsExec failed to relaunch as SYSTEM (exit $($p.ExitCode))."
    }
  } catch {
    Log "PsExec execution failed: $($_.Exception.Message)" Red
    Fatal "PsExec execution failed."
  }
  exit
}

function Try-Delete([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) {
    Log "Path not found, no deletion needed: $path" DarkCyan
    return $true
  }
  try {
    $file = [System.IO.File]::Open($path, 'Open', 'Read', 'None')
    $file.Close()
    Remove-Item -Path $path -Force -Recurse -ErrorAction Stop
    Log "Immediately deleted: $path" Green
    return $true
  } catch {
    Log "Failed to immediately delete $path : $($_.Exception.Message)" Yellow
    return $false
  }
}

function Queue-Delete([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) {
    Log "Path not found, skipping queue delete: $path" DarkCyan
    return
  }
  try {
    $reg = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $name = 'PendingFileRenameOperations'
    $cur = (Get-ItemProperty -Path $reg -Name $name -ErrorAction SilentlyContinue).$name
    if ($null -eq $cur) { $cur = @() }
    if ($path -notmatch '^(\\\\\?\\|\\\?\\)') { $path = "\\??\$path" }
    $new = @($cur + $path, '')
    Set-ItemProperty -Path $reg -Name $name -Type MultiString -Value $new -Force
    Log "Queued for delete on next boot: $path" Green
  } catch {
    Log "Failed to queue delete for $path : $($_.Exception.Message)" Yellow
  }
}

function Clean-ExistingLBFO {
  Log "Cleaning existing LBFO configurations" Cyan
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

  try {
    $out = (& netcfg.exe -u ms_lbfo) 2>&1
    Log "netcfg -u ms_lbfo output: $out" DarkCyan
  } catch {
    Log "netcfg -u ms_lbfo failed: $($_.Exception.Message)" Yellow
  }

  $cnBase = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\$ClassGuidNS"
  $cnInst = Join-Path $cnBase $InstanceGuid
  if (Test-Path $cnInst) {
    try {
      Remove-Item $cnInst -Recurse -Force -ErrorAction Stop
      Log "Removed $cnInst" DarkCyan
    } catch {
      Log "Failed to remove $cnInst : $($_.Exception.Message)" Yellow
    }
  }

  try {
    Get-ChildItem $cnBase -ErrorAction SilentlyContinue |
      Where-Object { $_.PSChildName -match '^{.*}$' } |
      ForEach-Object {
        $p = $_.PSPath
        $cid = (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).ComponentId
        if ($cid -eq $ComponentId) {
          Remove-Item $p -Recurse -Force -ErrorAction Stop
          Log "Removed additional Control\Network entry: $p" DarkCyan
        }
      }
  } catch {
    Log "Control\Network cleanup failed: $($_.Exception.Message)" Yellow
  }

  $ccBase = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$ClassGuidNS"
  if (Test-Path $ccBase) {
    Get-ChildItem $ccBase -ErrorAction SilentlyContinue |
      Where-Object { $_.PSChildName -match '^\d{4}$' } |
      ForEach-Object {
        $p = $_.PSPath
        $cid = (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).ComponentId
        $nci = (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).NetCfgInstanceId
        if ($cid -eq $ComponentId -or $nci -eq $InstanceGuid) {
          try {
            Remove-Item $p -Recurse -Force -ErrorAction Stop
            Log "Removed $p" DarkCyan
          } catch {
            Log "Failed to remove $p : $($_.Exception.Message)" Yellow
          }
        }
      }
  }

  $eventLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System\$SvcName"
  if (Test-Path $eventLogPath) {
    try {
      Remove-Item $eventLogPath -Recurse -Force -ErrorAction Stop
      Log "Removed $eventLogPath" DarkCyan
    } catch {
      Log "Failed to remove $eventLogPath : $($_.Exception.Message)" Yellow
    }
  }

  $driversHiveLoaded = $false
  try {
    if (-not (Get-Item 'HKLM:\DRIVERS' -ErrorAction SilentlyContinue)) {
      reg.exe load HKLM\DRIVERS "$env:WINDIR\System32\Config\DRIVERS" | Out-Null
      $driversHiveLoaded = $true
      Log "Loaded DRIVERS hive for cleanup" DarkCyan
    }
  } catch {
    Log "Failed to load DRIVERS hive: $($_.Exception.Message)" Yellow
  }

  try {
    $dd = 'HKLM:\DRIVERS\DriverDatabase'
    $devIds = Join-Path $dd "DeviceIds\$ComponentId"
    if (Test-Path $devIds) {
      Remove-Item $devIds -Recurse -Force -ErrorAction Stop
      Log "Removed $devIds" DarkCyan
    }

    $infFiles = Join-Path $dd 'DriverInfFiles\mslbfoprovider.inf'
    if (Test-Path $infFiles) {
      Remove-Item $infFiles -Recurse -Force -ErrorAction Stop
      Log "Removed $infFiles" DarkCyan
    }

    $pkgRoot = Join-Path $dd 'DriverPackages'
    if (Test-Path $pkgRoot) {
      Get-ChildItem $pkgRoot -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like 'mslbfoprovider.inf_amd64_*' } |
        ForEach-Object {
          Remove-Item $_.PSPath -Recurse -Force -ErrorAction Stop
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

  $filesToDelete = @(
    "$env:WINDIR\System32\drivers\mslbfoprovider.sys",
    "$env:WINDIR\System32\drivers\en-US\mslbfoprovider.sys.mui",
    "$env:WINDIR\System32\DriverStore\en-US\MsLbfoProvider.inf_loc",
    "$env:WINDIR\INF\$InfNameDst",
    "$env:WINDIR\System32\DriverStore\FileRepository\$InfFolder\*"
  )
  foreach ($file in $filesToDelete) {
    if (-not (Try-Delete $file)) {
      Log "Queuing deletion for $file as it could not be deleted immediately" Yellow
      Queue-Delete $file
    }
  }
}

function Copy-Strict($src, $dst, [string]$what) {
  if (-not (Test-Path $src)) {
    Fatal "Missing required ${what}: $src"
  }
  New-Item -ItemType Directory -Path (Split-Path $dst -Parent) -Force | Out-Null
  Log "Copying ${what}:`n  from $src`n    to $dst" Green
  try {
    if (Test-Path $dst) {
      try {
        Stop-Service -Name $SvcName -Force -ErrorAction SilentlyContinue
        Log "Stopped $SvcName service to unlock $dst" DarkCyan
      } catch {
        Log "Could not stop $SvcName service: $($_.Exception.Message)" Yellow
      }
      if (-not (Try-Delete $dst)) {
        Log "Could not delete existing $dst; attempting to overwrite" Yellow
      }
    }
    Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
  } catch {
    Fatal "Failed to copy ${what}: $($_.Exception.Message)"
  }
}

function Copy-ExtractedTree {
  $SourceRoot = Join-Path $PSScriptRoot "extracted\$ImageIndex"
  Log "Copying entire extracted tree to C:\" Cyan
  try {
    $out = (& xcopy.exe /H /Y /E "$SourceRoot\*" "C:\") 2>&1
    Log "xcopy output: $out" DarkCyan
  } catch {
    Log "xcopy failed: $($_.Exception.Message)" Red
    Fatal "Failed to copy extracted tree to C:\"
  }
}

function Ensure-DriversHiveLoaded {
  if (-not (Test-Path 'HKLM:\DRIVERS')) {
    $DrvHive = Join-Path $env:WINDIR 'System32\Config\DRIVERS'
    Log "Loading DRIVERS hive: $DrvHive" DarkCyan
    try {
      $p = Start-Process -FilePath 'reg.exe' -ArgumentList @('load', 'HKLM\DRIVERS', "`"$DrvHive`"") -PassThru -Wait -WindowStyle Hidden -ErrorAction Stop
      if ($p.ExitCode -ne 0) { Fatal "Failed to load DRIVERS hive (exit $($p.ExitCode))." }
      $global:DriversHiveWasLoadedByUs = $true
    } catch {
      Fatal "Failed to load DRIVERS hive: $($_.Exception.Message)"
    }
  } else {
    Log "DRIVERS hive already loaded; skipping load." DarkCyan
  }
}

function Maybe-Unload-DriversHive {
  if ($global:DriversHiveWasLoadedByUs) {
    Log "Unloading DRIVERS hive..." DarkCyan
    try {
      Start-Process -FilePath 'reg.exe' -ArgumentList @('unload', 'HKLM\DRIVERS') -Wait -WindowStyle Hidden -ErrorAction Stop | Out-Null
    } catch {
      Log "Failed to unload DRIVERS hive: $($_.Exception.Message)" Yellow
    }
  } else {
    Log "DRIVERS hive was not loaded by this script; leaving mounted." DarkCyan
  }
}

function Install-Catalogs {
  $catRoot = "C:\Windows\System32\CatRoot\$CatGUID"
  $catFeat = Get-ChildItem $catRoot -Filter 'Microsoft-Windows-Server-Features-Package016~31bf3856ad364e35~amd64~~10.0.20348.*.cat' | Select-Object -First 1
  $catDrv = Get-ChildItem $catRoot -Filter 'Microsoft-Windows-ServerCore-Drivers-merged-Package~31bf3856ad364e35~amd64~~10.0.20348.*.cat' | Select-Object -First 1
  if (-not $catFeat -or -not $catDrv) { Fatal "Could not find catalog files in $catRoot" }
  $catFeatPath = $catFeat.FullName
  $catDrvPath = $catDrv.FullName
  Log "Catalogs found: $catFeatPath, $catDrvPath" DarkCyan
  try {
    & certutil -addstore TrustedPublisher $catFeatPath | Out-Null
    & certutil -addstore Root $catFeatPath | Out-Null
    & certutil -addstore TrustedPublisher $catDrvPath | Out-Null
    & certutil -addstore Root $catDrvPath | Out-Null
    Log "Added catalogs to TrustedPublisher and Root stores" Green
  } catch {
    Log "Failed to add catalogs to certificate stores: $($_.Exception.Message)" Red
    throw $_
  }
}

function New-ControlClassEntry {
  $ClsRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$ClassGuidNS"
  $idx = 0
  while (Test-Path (Join-Path $ClsRoot ('{0:D4}' -f $idx))) { $idx++ }
  $CKey = Join-Path $ClsRoot ('{0:D4}' -f $idx)
  Log "Creating Control\Class key: $CKey" DarkCyan

  try {
    New-Item $CKey -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $CKey -Name 'ComponentId' -Value $ComponentId -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $CKey -Name 'InfPath' -Value $InfNameDst -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $CKey -Name 'InfSection' -Value 'Install' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $CKey -Name 'NetCfgInstanceId' -Value $InstanceGuid -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $CKey -Name 'Characteristics' -Value 0x40000 -PropertyType DWord -Force -ErrorAction Stop | Out-Null

    New-Item -Path "$CKey\Ndi" -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$CKey\Ndi" -Name 'Service' -Value 'MsLbfoProvider' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$CKey\Ndi" -Name 'CoServices' -Value @('MsLbfoProvider') -PropertyType MultiString -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$CKey\Ndi" -Name 'HelpText' -Value '@%SystemRoot%\System32\drivers\MsLbfoProvider.sys,-500' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$CKey\Ndi" -Name 'FilterClass' -Value 'ms_implatform' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$CKey\Ndi" -Name 'FilterType' -Value 2 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$CKey\Ndi" -Name 'FilterRunType' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null

    New-Item -Path "$CKey\Ndi\Interfaces" -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$CKey\Ndi\Interfaces" -Name 'UpperRange' -Value 'noupper' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$CKey\Ndi\Interfaces" -Name 'LowerRange' -Value 'nolower' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$CKey\Ndi\Interfaces" -Name 'FilterMediaTypes' -Value 'ms_implatform' -PropertyType String -Force -ErrorAction Stop | Out-Null
  } catch {
    Fatal "Failed to create Control\Class entry $CKey : $($_.Exception.Message)"
  }

  return $CKey
}

function New-ControlNetworkEntry {
  $NKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\$ClassGuidNS\$InstanceGuid"
  Log "Creating Control\Network instance: $NKey" DarkCyan

  try {
    New-Item $NKey -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $NKey -Name 'ComponentId' -Value $ComponentId -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $NKey -Name 'NetCfgInstanceId' -Value $InstanceGuid -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $NKey -Name 'Characteristics' -Value 0x40000 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $NKey -Name 'InfPath' -Value $InfNameDst -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $NKey -Name 'InfSection' -Value 'Install' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $NKey -Name 'Description' -Value '@%SystemRoot%\System32\drivers\MsLbfoProvider.sys,-501' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $NKey -Name 'LocDescription' -Value '@%SystemRoot%\System32\drivers\MsLbfoProvider.sys,-501' -PropertyType String -Force -ErrorAction Stop | Out-Null

    New-Item -Path "$NKey\Ndi" -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$NKey\Ndi" -Name 'Service' -Value 'MsLbfoProvider' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$NKey\Ndi" -Name 'CoServices' -Value @('MsLbfoProvider') -PropertyType MultiString -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$NKey\Ndi" -Name 'HelpText' -Value '@%SystemRoot%\System32\drivers\MsLbfoProvider.sys,-500' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$NKey\Ndi" -Name 'FilterClass' -Value 'ms_implatform' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$NKey\Ndi" -Name 'FilterType' -Value 2 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$NKey\Ndi" -Name 'FilterRunType' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null

    New-Item -Path "$NKey\Ndi\Interfaces" -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$NKey\Ndi\Interfaces" -Name 'UpperRange' -Value 'noupper' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$NKey\Ndi\Interfaces" -Name 'LowerRange' -Value 'nolower' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "$NKey\Ndi\Interfaces" -Name 'FilterMediaTypes' -Value 'ms_implatform' -PropertyType String -Force -ErrorAction Stop | Out-Null
  } catch {
    Fatal "Failed to create Control\Network entry $NKey : $($_.Exception.Message)"
  }

  return $NKey
}

function Install-Catalogs {
  $catRoot = "C:\Windows\System32\CatRoot\$CatGUID"
  $catFeat = Get-ChildItem $catRoot -Filter 'Microsoft-Windows-Server-Features-Package016~31bf3856ad364e35~amd64~~10.0.20348.*.cat' | Select-Object -First 1
  $catDrv = Get-ChildItem $catRoot -Filter 'Microsoft-Windows-ServerCore-Drivers-merged-Package~31bf3856ad364e35~amd64~~10.0.20348.*.cat' | Select-Object -First 1
  if (-not $catFeat -or -not $catDrv) { Fatal "Could not find catalog files in $catRoot" }
  $catFeatPath = $catFeat.FullName
  $catDrvPath = $catDrv.FullName
  Log "Catalogs found: $catFeatPath, $catDrvPath" DarkCyan
  try {
    & certutil -addstore TrustedPublisher $catFeatPath | Out-Null
    & certutil -addstore Root $catFeatPath | Out-Null
    & certutil -addstore TrustedPublisher $catDrvPath | Out-Null
    & certutil -addstore Root $catDrvPath | Out-Null
    Log "Added catalogs to TrustedPublisher and Root stores" Green
  } catch {
    Log "Failed to add catalogs to certificate stores: $($_.Exception.Message)" Red
    throw $_
  }
}

function Install-NetService {
  $infSrc = "C:\Windows\System32\DriverStore\FileRepository\$InfFolder\mslbfoprovider.inf"
  $infDst = "C:\Windows\INF\$InfNameDst"
  if (-not (Test-Path $infSrc)) { Fatal "INF missing at $infSrc" }

  # Copy INF to C:\Windows\INF
  Copy-Strict $infSrc $infDst "INF (destination name $InfNameDst)"

  # Log file hashes
  Log "Computing file hashes for verification" DarkCyan
  try {
    $sysHash = (Get-FileHash -Path (Join-Path $env:WINDIR 'System32\drivers\mslbfoprovider.sys') -Algorithm SHA256).Hash
    $infHash = (Get-FileHash -Path $infDst -Algorithm SHA256).Hash
    Log "mslbfoprovider.sys SHA256: $sysHash" DarkCyan
    Log "mslbfoprovider.inf SHA256: $infHash" DarkCyan
  } catch {
    Log "File hash computation failed: $($_.Exception.Message)" Yellow
  }

  # Verify driver signature
  Log "Verifying driver signature with sigcheck64" DarkCyan
  $sigcheck = Join-Path $PSScriptRoot 'sigcheck64.exe'
  if (-not (Test-Path $sigcheck)) {
    Fatal "sigcheck64.exe not found at: $sigcheck. Place sigcheck64.exe beside Install-LBFO.ps1 and run again."
  }
  try {
    $out = (& $sigcheck -accepteula -i "$env:WINDIR\System32\drivers\mslbfoprovider.sys") 2>&1
    Log "sigcheck64 output: $out" DarkCyan
  } catch {
    Log "sigcheck64 failed: $($_.Exception.Message)" Yellow
  }

  # Install driver using pnputil
  Log "Installing driver via pnputil: $infSrc" DarkCyan
  $success = $false
  try {
    $out = (& pnputil.exe /add-driver "$infSrc" /install) 2>&1
    Log "pnputil output: $out" DarkCyan
    if ($out -match 'Failed') {
      Log "pnputil failed to install driver" Red
      return $false
    }
    $success = $true
  } catch {
    Log "pnputil failed: $($_.Exception.Message)" Red
    return $false
  }

  # Install service using netcfg -l
  Log "Installing NetService via netcfg -l: $infDst" DarkCyan
  try {
    $out = (& netcfg.exe -v -l "$infDst" -c s -i $ComponentId) 2>&1
    Log "netcfg -l output: $out" DarkCyan
    if ($out -match 'failed') {
      Log "netcfg -l failed to install ms_lbfo" Red
      $success = $false
    }
  } catch {
    Log "netcfg -l failed: $($_.Exception.Message)" Red
    $success = $false
  }

  # Check if service exists before attempting to start
  Log "Checking if mslbfoprovider service exists before starting" DarkCyan
  try {
    $out = (& sc.exe query $SvcName) 2>&1
    if ($out -match 'SERVICE_NAME: mslbfoprovider') {
      Log "Attempting to start mslbfoprovider service" DarkCyan
      try {
        $out = (& sc.exe start $SvcName) 2>&1
        Log "sc start mslbfoprovider output: $out" DarkCyan
      } catch {
        Log "sc start mslbfoprovider failed: $($_.Exception.Message)" Yellow
        $success = $false
      }
    } else {
      Log "Service mslbfoprovider not yet registered; will attempt start after reboot" Yellow
      $success = $true  # Not a failure, as reboot will handle this
    }
  } catch {
    Log "sc query mslbfoprovider failed: $($_.Exception.Message)" Yellow
    $success = $true  # Not a failure, as reboot will handle this
  }

  # Check enumeration
  Log "Checking NetCfg services for ms_lbfo (may not appear until after reboot)" DarkCyan
  try {
    $out = (& netcfg.exe -s s) 2>&1
    $hits = $out | Where-Object { $_ -match 'ms_lbfo' }
    if ($hits) {
      $hits | ForEach-Object { Log "Found: $_" Green }
      $success = $true
    } else {
      Log "No ms_lbfo found in netcfg -s s (expected pre-reboot)" Yellow
      $success = $true  # Not a failure, as reboot will handle this
    }
  } catch {
    Log "netcfg -s s failed: $($_.Exception.Message)" Red
    $success = $false
  }

  return $success
}

function Stage-And-Install {
  Log "== Staging and installing LBFO provider ==" Cyan
  New-Item -ItemType Directory -Path $ProgramDataDir -Force | Out-Null
  "`n==== LBFO Install log start $(Get-Date) ====`n" | Set-Content -Path $LogPath -Encoding UTF8

  # Clean existing LBFO configurations
  Clean-ExistingLBFO

  # Copy entire extracted tree to C:\
  Copy-ExtractedTree

  # Install catalogs
  Install-Catalogs

  # Service
  Log "Configuring service: HKLM\SYSTEM\CurrentControlSet\Services\$SvcName" DarkCyan
  try {
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$SvcName" /v Start /t REG_DWORD /d 2 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$SvcName" /v Type /t REG_DWORD /d 1 /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$SvcName" /v Group /t REG_SZ /d NDIS /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$SvcName" /v ImagePath /t REG_EXPAND_SZ /d "\SystemRoot\System32\drivers\MsLbfoProvider.sys" /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$SvcName" /v Description /t REG_SZ /d "@%SystemRoot%\System32\drivers\MsLbfoProvider.sys,-501" /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$SvcName" /v DisplayName /t REG_SZ /d "@%SystemRoot%\System32\drivers\MsLbfoProvider.sys,-501" /f | Out-Null
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$SvcName" /v ErrorControl /t REG_DWORD /d 1 /f | Out-Null
  } catch {
    Log "Failed to configure service: $($_.Exception.Message)" Red
    throw $_
  }

  # EventLog
  Log "Configuring EventLog: HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System\$SvcName" DarkCyan
  try {
    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System\$SvcName" /v ProviderGuid /t REG_EXPAND_SZ /d "{387ed463-8b1b-42c9-9ef0-803fddf5d94e}" /f | Out-Null
  } catch {
    Log "Failed to configure EventLog: $($_.Exception.Message)" Red
    throw $_
  }

  # DRIVERS hive
  Ensure-DriversHiveLoaded

  $Leaf = $InfFolder
  Log "Populating HKLM\DRIVERS DriverDatabase..." DarkCyan
  try {
    New-Item -Path "HKLM:\DRIVERS\DriverDatabase\DeviceIds\$ComponentId" -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "HKLM:\DRIVERS\DriverDatabase\DeviceIds\$ComponentId" -Name 'mslbfoprovider.inf' -Value ([byte[]]@(1, 255, 0, 0)) -PropertyType Binary -Force -ErrorAction Stop | Out-Null
    New-Item -Path "HKLM:\DRIVERS\DriverDatabase\DriverInfFiles\mslbfoprovider.inf" -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "HKLM:\DRIVERS\DriverDatabase\DriverInfFiles\mslbfoprovider.inf" -Name '(default)' -Value $Leaf -PropertyType MultiString -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "HKLM:\DRIVERS\DriverDatabase\DriverInfFiles\mslbfoprovider.inf" -Name 'Active' -Value $Leaf -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-Item -Path "HKLM:\DRIVERS\DriverDatabase\DriverPackages\$Leaf" -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "HKLM:\DRIVERS\DriverDatabase\DriverPackages\$Leaf" -Name 'Version' -Value ([byte[]]@(255, 255, 9, 0, 0, 0, 0, 0, 116, 233, 54, 77, 37, 227, 206, 17, 191, 193, 8, 0, 43, 0, 225, 3, 24, 128, 140, 163, 197, 148, 198, 1, 1, 0, 124, 79, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0)) -PropertyType Binary -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "HKLM:\DRIVERS\DriverDatabase\DriverPackages\$Leaf" -Name 'Provider' -Value 'Microsoft' -PropertyType String -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "HKLM:\DRIVERS\DriverDatabase\DriverPackages\$Leaf" -Name 'SignerScore' -Value 0x0D000003 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "HKLM:\DRIVERS\DriverDatabase\DriverPackages\$Leaf" -Name 'FileSize' -Value 0x0000000000000CAA -PropertyType QWord -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -Path "HKLM:\DRIVERS\DriverDatabase\DriverPackages\$Leaf" -Name '(default)' -Value 'mslbfoprovider.inf' -PropertyType String -Force -ErrorAction Stop | Out-Null
  } catch {
    Log "Failed to populate HKLM\DRIVERS DriverDatabase: $($_.Exception.Message)" Red
    throw $_
  }

  # Control\Network + Control\Class
  $nk = New-ControlNetworkEntry
  $ck = New-ControlClassEntry

  # Persist context
  New-Item -ItemType Directory -Path $ProgramDataDir -Force | Out-Null
  @{
    RepoLeaf     = $Leaf
    InstanceGuid = $InstanceGuid
    ClassGuid    = $ClassGuidNS
    ComponentId  = $ComponentId
    InfNameDst   = $InfNameDst
  } | ConvertTo-Json | Set-Content -Path $CfgPath -Encoding UTF8
  Log "Saved context: $CfgPath" DarkCyan

  # Install NetService and start service
  $success = Install-NetService
  Maybe-Unload-DriversHive

  # Log final service state
  Log "Final service state check:" DarkCyan
  try {
    $out = (& sc.exe query mslbfoprovider) 2>&1
    Log "sc query mslbfoprovider output: $out" DarkCyan
  } catch {
    Log "sc query mslbfoprovider failed: $($_.Exception.Message)" Yellow
  }

  # Force reboot to ensure enumeration
  Log "Rebooting in 5 seconds to ensure service enumeration (Ctrl+C to cancel)..." Yellow
  Start-Sleep -Seconds 5
  Start-Process "shutdown.exe" -ArgumentList "/r /t 0" -WindowStyle Hidden
}

# ---- main ----
try {
  New-Item -ItemType Directory -Path $ProgramDataDir -Force | Out-Null
  Ensure-System
  Stage-And-Install
} catch {
  Fatal $_.Exception.Message
}