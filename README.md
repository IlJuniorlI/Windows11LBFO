# Windows11LBFO

This repository provides scripts to enable Load Balancing/Failover (LBFO) and NIC teaming on Windows 11 installations, which is not natively supported. The `Install-LBFO.ps1` script installs the LBFO provider, `Uninstall-LBFO.ps1` removes it, and `Verify-LBFO-Cleanup.ps1` checks for residual LBFO configurations. The repository includes the necessary extracted Server 2022 Index 4 files in the `extracted\4` folder, along with `PsExec.exe` and `sigcheck64.exe` from Sysinternals.

## Prerequisites
- Windows 11 system with administrative privileges.
- PowerShell (included with Windows 11).
- The `extracted\4` folder, `PsExec.exe`, and `sigcheck64.exe` are already included in the repository.

## Installation
1. **Clone or Download the Repository**:
   - Clone the repository or download and extract the ZIP file to a folder, e.g., `C:\Temp\Windows11LBFO`.
   - Ensure `PsExec.exe`, `sigcheck64.exe`, and the `extracted\4` folder are in the repository root.

2. **Run the Install Script**:
   - Open an elevated PowerShell prompt (Run as Administrator).
   - Navigate to the repository folder:
     ```powershell
     cd C:\Temp\Windows11LBFO
     ```
   - Run the install script:
     ```powershell
     powershell -ExecutionPolicy Bypass -File .\Install-LBFO.ps1
     ```
   - The script will:
     - Clean existing LBFO configurations.
     - Copy driver files from `extracted\4` to `C:\Windows\...`.
     - Register driver catalogs for trust.
     - Install the LBFO provider using `pnputil` and `netcfg`.
     - Set up necessary registry entries.
     - Reboot the system to complete enumeration.

3. **Verify Installation (Post-Reboot)**:
   - After the automatic reboot, open an elevated PowerShell prompt.
   - Run these commands to confirm LBFO is enabled:
     ```powershell
     type C:\ProgramData\LBFO\install.log
     sc.exe query mslbfoprovider
     netcfg -q ms_lbfo
     Get-NetLbfoTeam
     Get-NetAdapter | Select-Object Name, Status, LinkSpeed
     New-NetLbfoTeam -Name "Team0" -TeamNicName "Team0" -TeamMembers "Ethernet" -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Verbose -ErrorAction SilentlyContinue
     ```
   - Expected output:
     - `install.log`: Shows successful cleanup, file copy, catalog registration, and driver installation.
     - `sc.exe query mslbfoprovider`: Shows `STATE: 4 RUNNING` or `1 STOPPED`.
     - `netcfg -q ms_lbfo`: Shows `ms_lbfo is installed`.
     - `Get-NetLbfoTeam`: Lists `Team0` if created, or nothing if not yet created.
     - `Get-NetAdapter`: Lists network adapters (e.g., `Ethernet Up 2.5 Gbps`).
     - `New-NetLbfoTeam`: Successfully creates `Team0`, possibly prompting for confirmation.

## Uninstallation
1. **Run the Uninstall Script**:
   - Open an elevated PowerShell prompt.
   - Navigate to the repository folder:
     ```powershell
     cd C:\Temp\Windows11LBFO
     ```
   - Run the uninstall script:
     ```powershell
     powershell -ExecutionPolicy Bypass -File .\Uninstall-LBFO.ps1
     ```
   - The script will:
     - Stop and delete the `mslbfoprovider` service.
     - Remove LBFO-related registry entries.
     - Delete driver files and DriverStore entries.
     - Queue file deletions for reboot if needed.
     - Reboot the system to complete cleanup.

2. **Verify Uninstallation**:
   - After reboot, run the verification script:
     ```powershell
     powershell -ExecutionPolicy Bypass -File .\Verify-LBFO-Cleanup.ps1
     ```
   - The script checks for residual LBFO configurations and logs results to `C:\ProgramData\LBFO\verify_cleanup.log`.
   - Expected output:
     - No `mslbfoprovider` service (`sc query mslbfoprovider` fails with error 1060).
     - No `ms_lbfo` in `netcfg -s s`.
     - No LBFO-related registry entries or files.

## Troubleshooting
- **Check Logs**:
  - Installation log: `C:\ProgramData\LBFO\install.log`
  - PsExec logs: `C:\ProgramData\LBFO\psexec_err.log`, `C:\ProgramData\LBFO\psexec_out.log`
  - Cleanup verification log: `C:\ProgramData\LBFO\verify_cleanup.log`
- **Test PsExec**:
  ```powershell
  C:\Temp\Windows11LBFO\PsExec.exe -accepteula -s -i -h powershell.exe -Command "whoami"
  ```
  Expected output: `nt authority\system`. If it fails, download a fresh `PsExec.exe` or disable antivirus temporarily.
- **Run Without PsExec**:
  Modify `Install-LBFO.ps1` or `Uninstall-LBFO.ps1` to skip PsExec by replacing the main block with:
  ```powershell
  try {
    New-Item -ItemType Directory -Path $ProgramDataDir -Force | Out-Null
    Stage-And-Install  # or Clean-LBFO for uninstall
  } catch {
    Fatal $_.Exception.Message
  }
  ```
  Then run as Administrator.
- **Verify Source Files**:
  ```powershell
  Test-Path 'C:\Temp\Windows11LBFO\extracted\4\Windows\System32\drivers\mslbfoprovider.sys'
  Test-Path 'C:\Temp\Windows11LBFO\extracted\4\Windows\System32\drivers\en-US\mslbfoprovider.sys.mui'
  Test-Path 'C:\Temp\Windows11LBFO\extracted\4\Windows\System32\DriverStore\en-US\MsLbfoProvider.inf_loc'
  Test-Path 'C:\Temp\Windows11LBFO\extracted\4\Windows\System32\DriverStore\FileRepository\mslbfoprovider.inf_amd64_f9d27a6b05ef21aa\mslbfoprovider.inf'
  Test-Path 'C:\Temp\Windows11LBFO\extracted\4\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\Microsoft-Windows-Server-Features-Package016~31bf3856ad364e35~amd64~~10.0.20348.3932.cat'
  Test-Path 'C:\Temp\Windows11LBFO\extracted\4\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\Microsoft-Windows-ServerCore-Drivers-merged-Package~31bf3856ad364e35~amd64~~10.0.20348.3932.cat'
  ```
- **Manual Install Test** (if needed):
  ```powershell
  $inf = "C:\Windows\INF\MsLbfoProvider.inf"
  pnputil /add-driver $inf /install
  netcfg -v -l $inf -c s -i ms_lbfo
  sc.exe start mslbfoprovider
  netcfg -s s | findstr /i ms_lbfo
  ```

## Notes
- **Teaming**: After installation, create NIC teams with `New-NetLbfoTeam`. Start with one adapter (e.g., "Ethernet") to avoid binding issues, then add more with `Add-NetLbfoTeamMember`.
- **Manual Installation**: If the script fails, use `ncpa.cpl` -> Have Disk, pointing to `C:\Windows\INF\MsLbfoProvider.inf`.
- **Support**: For issues, check logs and open an issue on the GitHub repository with the relevant log files and outputs.
