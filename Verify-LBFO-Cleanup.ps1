# Verify-LBFO-Cleanup.ps1
# Read-only audit for LBFO (MsLbfoProvider) remnants

$ErrorActionPreference = 'SilentlyContinue'
$results = @()

function Add-Result($Area, $Item, $Present) {
  $results += [pscustomobject]@{ Area = $Area; Item = $Item; Present = $Present }
}

Write-Host "=== LBFO (MsLbfoProvider) Cleanup Verification ===`n" -ForegroundColor Cyan

# 1) Service
$s = sc.exe query mslbfoprovider 2>$null
Add-Result 'Service' 'mslbfoprovider service exists' ($LASTEXITCODE -eq 0)

# 2) Driver files
$driver = "$env:SystemRoot\System32\drivers\MsLbfoProvider.sys"
$mui    = "$env:SystemRoot\System32\drivers\en-US\mslbfoprovider.sys.mui"
Add-Result 'Files' "Driver: $driver" (Test-Path $driver)
Add-Result 'Files' "MUI:    $mui"    (Test-Path $mui)

# 3) DriverStore
$ds = Get-ChildItem "$env:SystemRoot\System32\DriverStore\FileRepository\mslbfoprovider.inf_amd64_*" -Directory
Add-Result 'DriverStore' 'mslbfoprovider.inf_amd64_* present' ($ds -ne $null)

# 4) INF in \Windows\INF and any OEM INF that references mslbfoprovider
$infMain = "$env:SystemRoot\INF\MsLbfoProvider.inf"
Add-Result 'INF' "Main INF: $infMain" (Test-Path $infMain)
$oemRefs = Get-ChildItem "$env:SystemRoot\INF\oem*.inf" | Select-String -List -Pattern 'mslbfoprovider'
Add-Result 'INF' 'OEM oem*.inf referencing mslbfoprovider' ($oemRefs -ne $null)

# 5) Net service enumeration (should NOT list MS_LBFO)
$svcList = (netcfg.exe -s s 2>$null) | Out-String
Add-Result 'Enumeration' 'netcfg -s s shows MS_LBFO' ($svcList -match '(?i)\bMS_LBFO\b')
$compList = (netcfg.exe -e 2>$null) | Out-String
Add-Result 'Enumeration' 'netcfg -e shows MS_LBFO'   ($compList -match '(?i)\bMS_LBFO\b')

# 6) Control\Network instance key (GUID from INF)
$instGuid = '{fc66a602-b769-4666-a540-ca3df0e7df2c}'
$netKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\$instGuid"
Add-Result 'Registry-Control\Network' "Instance key exists: $netKey" (Test-Path $netKey)

# 7) Control\Class NetService instance entries with ComponentId=ms_lbfo
$classRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E974-E325-11CE-BFC1-08002BE10318}"
$classHits = @()
if (Test-Path $classRoot) {
  Get-ChildItem $classRoot -ErrorAction SilentlyContinue | ForEach-Object {
    $ci = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($ci.ComponentId -eq 'ms_lbfo') { $classHits += $_.PSChildName }
  }
}
Add-Result 'Registry-Control\Class' 'Any class instance with ComponentId=ms_lbfo' ($classHits.Count -gt 0)

# 8) DRIVERS hive: DriverDatabase entries (we’ll temporarily load if needed)
$driversMountedHere = $false
if (-not (Test-Path 'HKLM:\DRIVERS')) {
  try {
    reg.exe load HKLM\DRIVERS "$env:SystemRoot\System32\Config\DRIVERS" >$null 2>&1 | Out-Null
    $driversMountedHere = $true
  } catch {}
}

$drvA = 'HKLM:\DRIVERS\DriverDatabase\DeviceIds\ms_lbfo'
$drvB = 'HKLM:\DRIVERS\DriverDatabase\DriverInfFiles\mslbfoprovider.inf'
$drvC = 'HKLM:\DRIVERS\DriverDatabase\DriverPackages'
Add-Result 'Registry-DRIVERS' "DeviceIds\ms_lbfo" (Test-Path $drvA)
Add-Result 'Registry-DRIVERS' "DriverInfFiles\mslbfoprovider.inf" (Test-Path $drvB)
$pkgHit = $false
if (Test-Path $drvC) {
  $pkgHit = (Get-ChildItem $drvC | Where-Object { $_.PSChildName -like 'mslbfoprovider.inf_amd64_*' }).Count -gt 0
}
Add-Result 'Registry-DRIVERS' "DriverPackages\mslbfoprovider.inf_amd64_*" $pkgHit

# 9) Catalogs (if you asked to remove them, they should be gone; otherwise they may still be present)
$catRoot = Join-Path $env:SystemRoot 'System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
$catPatterns = @(
  'Microsoft-Windows-ServerCore-Drivers-merged-Package~31bf3856ad364e35~amd64~~10.0.20348.*.cat',
  'Microsoft-Windows-Server-Features-Package0*~31bf3856ad364e35~amd64~~10.0.20348.*.cat'
)
$cats = @()
foreach ($p in $catPatterns) {
  $cats += Get-ChildItem -Path (Join-Path $catRoot $p) -ErrorAction SilentlyContinue
}
Add-Result 'Catalogs' 'Server 2022 LBFO-related catalogs still present' ($cats.Count -gt 0)

# 10) Pending delete queue (ensures deletes were queued for next boot)
$pendingKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$pending = (Get-ItemProperty -Path $pendingKey -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
$pendingText = ($pending | Out-String)
$anyPending = $pendingText -match '(?i)mslbfoprovider|MsLbfoProvider\.inf'
Add-Result 'PendingDeletes' 'PendingFileRenameOperations contains LBFO files' $anyPending

# 11) Teams (should be none if you removed them)
try {
  $teams = Get-NetLbfoTeam -ErrorAction Stop
  Add-Result 'Teams' 'Existing LBFO team(s) still present' ($teams -ne $null -and $teams.Count -gt 0)
} catch {
  # If cmdlet throws on client SKU or missing provider, that is OK
  Add-Result 'Teams' 'Existing LBFO team(s) still present' $false
}

# Unload DRIVERS hive if we mounted it
if ($driversMountedHere) {
  try { reg.exe unload HKLM\DRIVERS >$null 2>&1 | Out-Null } catch {}
}

# ---- Report ----
Write-Host "`n--- Findings ---" -ForegroundColor Cyan
$results | Sort-Object Area, Item | Format-Table -AutoSize

$bad = $results | Where-Object { $_.Present -eq $true -and $_.Area -ne 'Catalogs' } # catalogs can be left intentionally
$ok  = $results | Where-Object { $_.Present -eq $false -or $_.Area -eq 'Catalogs' }

Write-Host "`n--- Summary ---" -ForegroundColor Cyan
if ($bad.Count -eq 0) {
  Write-Host "PASS: No LBFO service, driver, INF, DriverStore, or registry bindings detected." -ForegroundColor Green
  if ($cats.Count -gt 0) {
    Write-Host "Note: Catalogs are still present (harmless). Remove only if you explicitly want them gone." -ForegroundColor Yellow
  }
} else {
  Write-Host "ATTENTION: Some remnants were found:" -ForegroundColor Yellow
  $bad | Format-Table -AutoSize
  Write-Host @"
What to remove (post-checklist):
  - Service exists .......................... Disable it:  sc.exe config mslbfoprovider start= disabled
  - Driver file(s) present .................. Schedule delete on next boot (MoveFileEx/PendingFileRenameOperations)
  - DriverStore folder present .............. Use PendingFileRenameOperations to queue the folder for deletion
  - OEM INF references present .............. Delete the specific oemXX.inf + oemXX.pnf
  - Control\Network instance present ........ Remove its key
  - Control\Class instance(s) present ....... Remove any 000x instance with ComponentId=ms_lbfo
  - DRIVERS hive entries present ............ Remove the ms_lbfo DeviceIds/DriverInfFiles/DriverPackages entries
"@
}
