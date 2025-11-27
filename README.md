# CKMWinFix 

## Overview
**CKMWinFix.ps1** is an all-in-one Windows optimization and repair script designed to automatically diagnose, fix, clean, and optimize Windows 10 and Windows 11 systems.  
It combines system health checks, security scans, disk repair, junk cleanup, debloating, performance tuning, networking fixes, Windows Update management, software auditing, backups, and scheduled automation into a single self-contained tool.

The script is OS-aware: it detects whether it is running on Windows 10 or Windows 11 and applies the appropriate debloat and optimization steps for each.

**Quick start**

*Novice Users*
```
Download the zip file and move the folder to your desk top 
Right click on the Run-CKMWinFix.bat file and run as Administrator
Follow the prompts :)
```

*Advanced Users*
```git clone https://github.com/merlinthedev848/CKM-Win-Optimizer.git
cd CKM-Win-Optimizer
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
.\CKMWinFix.ps1
```
----
## Features
- **System Health Monitoring**
  - CPU, RAM, and disk usage reporting
  - Performance baseline comparison (CPU, RAM, disk I/O, network throughput)

- **Security**
  - Windows Defender signature update
  - Quick or full malware scan (toggleable)
  - Audit of running manual services

- **Repair**
  - System File Checker (`sfc /scannow`)
  - Deployment Image Servicing and Management (`DISM /RestoreHealth`)
  - Disk integrity check (`chkdsk`)

- **Cleanup**
  - Temp files, Prefetch, Windows Update cache, Delivery Optimization files
  - Empty recycle bin
  - Optional event log purge

- **Debloat (OS-aware)**
  - Windows 10: removes legacy apps, disables Cortana
  - Windows 11: removes Widgets, Teams, YourPhone, disables transparency
  - Common: disables telemetry and background apps

- **Performance Optimization**
  - Disables non-Microsoft startup items
  - Sets High Performance power plan
  - Trims visual effects for speed

- **Networking**
  - Flushes DNS cache
  - Resets Winsock and IP stack
  - Enables NIC features (RSS, autotuning, chimney offload)

- **Windows Update**
  - Installs updates via PSWindowsUpdate if available
  - Falls back to `UsoClient` if not

- **Software Audit**
  - Lists installed applications with version numbers

- **Backup**
  - Uses `robocopy` to back up user Documents folder
  - Skips junctions and logs results

- **Automation**
  - Registers a scheduled task to run daily at 3:00AM under SYSTEM with highest privileges

---

## Requirements
- Windows 10 or Windows 11
- PowerShell 5.1 or later
- Administrator privileges
- Optional: [PSWindowsUpdate](https://www.powershellgallery.com/packages/PSWindowsUpdate) module for advanced update handling

---

## Installation
1. Save the script as `CKMWinFix.ps1` in a folder of your choice (e.g., `C:\Scripts\CKMWinFix.ps1`).
2. Ensure PowerShell execution policy allows running scripts:
   ```
   powershell Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```    


**Run the Script Manually:**
```.\CKMWinFix.ps1
```

**On first run, it will:**
 - Perform all checks, fixes, and optimizations
 - Log results to Logs\HealthCheckLog_<timestamp>.txt
 - Register a scheduled task named AutomatedSystemHealthCheck to run daily at 3:00AM

**Configuration**
At the top of the script, you can toggle features:
```
 $Global:EnableDebloat     = $true    # Disable if you want to keep all built-in apps
 $Global:EnableFullScan    = $false   # Set true for full Defender scan
 $Global:EnableChkDsk      = $true    # Disable if you don't want CHKDSK
 $Global:ClearEventLogs    = $false   # Enable to purge event logs
 $Global:DoScheduleTask    = $true    # Disable if you don't want scheduled automation
```

**Logs**
 - Logs are stored in the Logs folder alongside the script.
 - Each run generates a timestamped log file.
 - Backup operations also append to the log.

**Notes**
 - CHKDSK: If the system drive is in use, CHKDSK will schedule itself for the next reboot.
 - Debloat: The script keeps essential apps (Store, Calculator, Notepad, Photos). Adjust the whitelist if you want to retain more.
 - Networking tweaks: RSS/autotuning are generally beneficial; chimney offload depends on NIC/driver support.
 - Windows Update: If PSWindowsUpdate is not installed, the script uses UsoClient commands.

**Disclaimer**
This script makes system-level changes. Test in a non-production environment first. 
Use at your own risk — while designed to fix 99.9% of common issues, no script can guarantee absolute coverage of all possible problems
