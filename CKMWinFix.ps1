# Master Windows Optimization & Repair Script (OS-aware for Windows 10/11)
# Run in elevated PowerShell (Administrator)

# =========================
# Setup and logging
# =========================
$LogFolder = "$PSScriptRoot\Logs"
if (!(Test-Path -Path $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder | Out-Null }
$LogFile = "$LogFolder\HealthCheckLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

Function Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "$Timestamp : $Message" | Tee-Object -FilePath $LogFile -Append
}

# =========================
# Feature toggles (set to $false to disable)
# =========================
$Global:EnableDebloat     = $true
$Global:EnableFullScan    = $false   # Defender full scan can be lengthy
$Global:EnableChkDsk      = $true    # May schedule next boot
$Global:ClearEventLogs    = $false   # Off by default; turn on if you want to purge
$Global:DoScheduleTask    = $true

# =========================
# Detect OS version and product
# =========================
$ProductReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$ProductName = $ProductReg.ProductName
$EditionID   = $ProductReg.EditionID
$ReleaseId   = $ProductReg.ReleaseId
$DisplayOS   = "$ProductName ($EditionID, Release $ReleaseId)"

Log "Detected OS: $DisplayOS"

# =========================
# Module handling (Windows Update)
# =========================
try {
    if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
        Import-Module PSWindowsUpdate -Force
        Log "PSWindowsUpdate module loaded."
    } else {
        Log "PSWindowsUpdate module not found. Using USOClient fallback."
    }
} catch { Log "Failed to import PSWindowsUpdate: $_" }

# =========================
# Health monitoring
# =========================
Function Check-SystemHealth {
    Log "Starting System Health Check..."
    Write-Host "=== System Health Summary ($DisplayOS) ==="

    try {
        $CPU = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue
        $RAM = Get-WmiObject -Class Win32_OperatingSystem
        $RAMFree = [math]::Round(($RAM.FreePhysicalMemory / 1MB), 2)
        $RAMTotal = [math]::Round(($RAM.TotalVisibleMemorySize / 1MB), 2)
        $RAMUsage = [math]::Round((($RAMTotal - $RAMFree) / $RAMTotal) * 100, 2)

        Write-Host "CPU Usage: $([math]::Round($CPU,2))%" -ForegroundColor Green
        Write-Host "Memory Usage: $RAMUsage% ($RAMFree GB free of $RAMTotal GB)" -ForegroundColor Green
    } catch { Log "Health counters error: $_" }

    try {
        Get-PSDrive -PSProvider FileSystem | ForEach-Object {
            $FreeGB = [math]::Round($_.Free / 1GB, 2)
            $TotalGB = [math]::Round(($_.Used + $_.Free) / 1GB, 2)
            Write-Host "Drive $($_.Name) - Free: $FreeGB GB of $TotalGB GB"
        }
    } catch { Log "Drive space listing error: $_" }

    Log "System Health Check Complete."
}

# =========================
# Security scans (Windows Defender)
# =========================
Function Ensure-Defender {
    Log "Checking Windows Defender installation..."
    try {
        $DefenderFeature = Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-Features -ErrorAction SilentlyContinue
        if ($DefenderFeature.State -ne "Enabled") {
            Write-Host "Windows Defender is not enabled. Installing..." -ForegroundColor Yellow
            Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-Features -All -NoRestart | Out-Null
            Log "Windows Defender feature enabled."
        } else {
            Log "Windows Defender is already enabled."
        }
    } catch {
        Log "Failed to check/enable Windows Defender: $_"
    }
}

Function Run-DefenderCLI {
    $MpCmd = "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"
    $Exe = Get-Item $MpCmd -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($Exe) {
        Write-Host "Running Defender CLI scan..." -ForegroundColor Yellow
        try {
            Start-Process $Exe.FullName -ArgumentList "-SignatureUpdate" -Wait
            if ($Global:EnableFullScan) {
                Start-Process $Exe.FullName -ArgumentList "-Scan -ScanType 2" -Wait  # 2 = Full
                Log "Defender Full Scan triggered via MpCmdRun.exe"
            } else {
                Start-Process $Exe.FullName -ArgumentList "-Scan -ScanType 1" -Wait  # 1 = Quick
                Log "Defender Quick Scan triggered via MpCmdRun.exe"
            }
        } catch {
            Log "Defender CLI scan error: $_"
        }
    } else {
        Log "MpCmdRun.exe not found. Windows Defender may not be installed. Skipping scan."
    }
}

Function Run-SecurityScans {
    Log "Starting Security Scans..."

    # Path to Defender CLI
    $MpCmd = "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"
    $Exe = Get-Item $MpCmd -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($Exe) {
        Write-Host "=== Updating Windows Defender Signatures (CLI) ===" -ForegroundColor Yellow
        try { Start-Process $Exe.FullName -ArgumentList "-SignatureUpdate" -Wait; Log "Defender signatures updated via CLI." }
        catch { Log "Defender signature update error: $_" }

        Write-Host "=== Running Windows Defender Scan (CLI) ===" -ForegroundColor Yellow
        try {
            if ($Global:EnableFullScan) {
                Start-Process $Exe.FullName -ArgumentList "-Scan -ScanType 2" -Wait  # 2 = Full
                Log "Defender Full Scan triggered via CLI."
            } else {
                Start-Process $Exe.FullName -ArgumentList "-Scan -ScanType 1" -Wait  # 1 = Quick
                Log "Defender Quick Scan triggered via CLI."
            }
        } catch { Log "Defender CLI scan error: $_" }
    } else {
        Log "Windows Defender CLI not found. Skipping Defender scan."
    }

    # Audit services
    Write-Host "Checking manual-start services currently running..." -ForegroundColor Yellow
    try {
        Get-Service | Where-Object { $_.StartType -eq "Manual" -and $_.Status -eq "Running" } | Format-Table -AutoSize
    } catch { Log "Service audit error: $_" }

    Log "Security Scans Completed."
}

# =========================
# Optimization tasks (cleanup, startup, visuals, power)
# =========================
Function Optimize-System {
    Log "Starting System Optimization..."

    # Cleanup
    Write-Host "Cleaning Temporary Files and Prefetch..." -ForegroundColor Yellow
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "Cleaning Windows Update cache..." -ForegroundColor Yellow
    try {
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Stop-Service -Name bits -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Windows\SoftwareDistribution\DataStore\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\ProgramData\USOShared\Logs\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\ProgramData\Microsoft\Windows\DeliveryOptimization\*" -Recurse -Force -ErrorAction SilentlyContinue
    } catch { Log "Update cache cleanup error: $_" }
    finally {
        Start-Service -Name bits -ErrorAction SilentlyContinue
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    }

    Write-Host "Emptying Recycle Bin..." -ForegroundColor Yellow
    try { Clear-RecycleBin -Force -ErrorAction SilentlyContinue } catch {}

    # Startup cleanup
    Write-Host "Disabling non-Microsoft startup items..." -ForegroundColor Yellow
    try {
        Get-CimInstance -Namespace "root\cimv2" -Class Win32_StartupCommand | Where-Object { $_.Command -notlike "*Windows*" } | ForEach-Object {
            Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $_.Name -ErrorAction SilentlyContinue
            Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $_.Name -ErrorAction SilentlyContinue
        }
    } catch { Log "Startup cleanup error: $_" }

    # Visual effects: performance oriented (applies to both, with extra for Win11 below)
    Write-Host "Optimizing visual effects..." -ForegroundColor Yellow
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -ErrorAction SilentlyContinue
        # UserPreferencesMask tuned for performance: hides some animations; may not persist on every build
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -ErrorAction SilentlyContinue
    } catch { Log "Visual effects tweak error: $_" }

    # Power plan High Performance
    Write-Host "Setting Power Plan to High Performance..." -ForegroundColor Yellow
    try { powercfg -setactive SCHEME_MIN } catch { Log "Power plan error: $_" }

    Log "Optimization Completed."
}

# =========================
# Automated troubleshooting (SFC, DISM, DNS)
# =========================
Function Troubleshoot-Issues {
    Log "Starting Troubleshooting..."

    # System File Checker
    Write-Host "=== Running System File Checker (SFC /scannow) ===" -ForegroundColor Yellow
    $StartTime = Get-Date
    try {
        # Run SFC and stream output directly to console
        cmd /c "sfc /scannow"
        $EndTime = Get-Date
        $Duration = $EndTime - $StartTime
        Write-Host "SFC completed in $($Duration.Minutes)m $($Duration.Seconds)s" -ForegroundColor Green
        Log "SFC completed in $($Duration.Minutes)m $($Duration.Seconds)s."
    } catch { Log "SFC error: $_" }

    # DISM RestoreHealth
    Write-Host "=== Running DISM /RestoreHealth ===" -ForegroundColor Yellow
    $StartTime = Get-Date
    try {
        cmd /c "DISM /Online /Cleanup-Image /RestoreHealth"
        $EndTime = Get-Date
        $Duration = $EndTime - $StartTime
        Write-Host "DISM completed in $($Duration.Minutes)m $($Duration.Seconds)s" -ForegroundColor Green
        Log "DISM completed in $($Duration.Minutes)m $($Duration.Seconds)s."
    } catch { Log "DISM error: $_" }

    # DNS Flush
    Write-Host "=== Flushing DNS Cache ===" -ForegroundColor Yellow
    try { ipconfig /flushdns | Out-Host; Log "DNS cache flushed." } catch { Log "DNS flush error: $_" }

    Log "Troubleshooting Completed."
}


# =========================
# Disk integrity (CHKDSK)
# =========================
Function Check-DiskIntegrity {
    if ($Global:EnableChkDsk) {
        Log "Checking Disk Integrity (CHKDSK)..."
        Write-Host "=== Running CHKDSK on C: (verbose mode, may require reboot) ===" -ForegroundColor Yellow

        try {
            $StartTime = Get-Date
            Write-Host "CHKDSK started at $StartTime" -ForegroundColor Cyan

            # Run CHKDSK and stream verbose output directly to console
            cmd /c "chkdsk C: /F /R /V"

            $EndTime = Get-Date
            $Duration = $EndTime - $StartTime
            Write-Host "CHKDSK finished at $EndTime" -ForegroundColor Green
            Write-Host "Total runtime: $($Duration.Hours)h $($Duration.Minutes)m $($Duration.Seconds)s" -ForegroundColor Green
            Log "CHKDSK completed in $($Duration.Hours)h $($Duration.Minutes)m $($Duration.Seconds)s."
        } catch {
            Log "CHKDSK error: $_"
        }
    } else {
        Log "CHKDSK disabled by toggle."
    }
}

# =========================
# Windows updates (PSWindowsUpdate or USOClient fallback)
# =========================
Function Check-WindowsUpdates {
    Log "Checking for Windows Updates..."
    Write-Host "Checking for Windows Updates..." -ForegroundColor Yellow
    if (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue) {
        try { Get-WindowsUpdate -Install -AcceptAll -AutoReboot | Out-Null; Log "Windows Updates installed via PSWindowsUpdate." }
        catch { Log "Error running Get-WindowsUpdate: $_"; Write-Host "An error occurred while checking updates: $_" -ForegroundColor Red }
    } else {
        try {
            UsoClient StartScan
            UsoClient StartDownload
            UsoClient StartInstall
            Log "Windows Updates triggered via USOClient."
        } catch { Log "USOClient update trigger error: $_" }
    }
}

# =========================
# Software audit (x64 + x86)
# =========================
Function Audit-Software {
    Log "Auditing Installed Software..."
    try {
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Sort-Object DisplayName |
        ForEach-Object { Write-Host "$($_.DisplayName): Version $($_.DisplayVersion)" }
    } catch { Log "Software audit error: $_" }
    Log "Software Audit Completed."
}

# =========================
# Performance baseline (adds disk I/O and network throughput)
# =========================
Function Compare-PerformanceBaseline {
    $BaselineFile = "$PSScriptRoot\PerformanceBaseline.json"
    Log "Comparing Performance Metrics with Baseline..."
    try {
        $DiskIORead = (Get-Counter '\PhysicalDisk(_Total)\Disk Read Bytes/sec').CounterSamples[0].CookedValue
        $DiskIOWrite = (Get-Counter '\PhysicalDisk(_Total)\Disk Write Bytes/sec').CounterSamples[0].CookedValue
        $NetBytes = (Get-Counter '\Network Interface(*)\Bytes Total/sec').CounterSamples | Measure-Object CookedValue -Sum | Select-Object -ExpandProperty Sum

        $CurrentMetrics = @{
            CPUUsage     = [math]::Round((Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue,2)
            RAMUsageMB   = [math]::Round(((Get-WmiObject Win32_OperatingSystem).TotalVisibleMemorySize - (Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory) / 1MB, 2)
            DiskReadBps  = [math]::Round($DiskIORead, 0)
            DiskWriteBps = [math]::Round($DiskIOWrite, 0)
            NetworkBps   = [math]::Round($NetBytes, 0)
        }

        if (Test-Path $BaselineFile) {
            $BaselineMetrics = Get-Content -Path $BaselineFile | ConvertFrom-Json
            Write-Host "=== Performance Baseline Comparison ==="
            Write-Host "CPU Usage: Current = $($CurrentMetrics.CPUUsage)% | Baseline = $($BaselineMetrics.CPUUsage)%"
            Write-Host "RAM Usage: Current = $($CurrentMetrics.RAMUsageMB) MB | Baseline = $($BaselineMetrics.RAMUsageMB) MB"
            Write-Host "Disk Read: Current = $($CurrentMetrics.DiskReadBps) B/s | Baseline = $($BaselineMetrics.DiskReadBps) B/s"
            Write-Host "Disk Write: Current = $($CurrentMetrics.DiskWriteBps) B/s | Baseline = $($BaselineMetrics.DiskWriteBps) B/s"
            Write-Host "Network: Current = $($CurrentMetrics.NetworkBps) B/s | Baseline = $($BaselineMetrics.NetworkBps) B/s"
        } else {
            Write-Host "No baseline found. Saving current metrics as baseline."
            $CurrentMetrics | ConvertTo-Json | Set-Content -Path $BaselineFile
        }
        Log "Baseline Comparison Completed."
    } catch { Log "Baseline metrics error: $_" }
}

# =========================
# Backup (robocopy, skips junctions, logs to file)
# =========================
Function Backup-UserData {
    Log "Starting Backup of User Data..."
    $BackupSource = "$env:USERPROFILE\Documents"
    $BackupDestination = "$PSScriptRoot\Backups"
    if (!(Test-Path -Path $BackupDestination)) { New-Item -ItemType Directory -Path $BackupDestination | Out-Null }

    $RoboArgs = "`"$BackupSource`" `"$BackupDestination`" /E /COPY:DAT /R:1 /W:1 /NFL /NDL /NP /XA:SH /XJ /LOG:$LogFile"
    try {
        Start-Process -FilePath "robocopy.exe" -ArgumentList $RoboArgs -Wait
        Write-Host "Backup Completed: $BackupSource to $BackupDestination" -ForegroundColor Green
        Log "Backup Completed."
    } catch { Log "Backup error: $_"; Write-Host "Backup encountered an error: $_" -ForegroundColor Red }
}

# =========================
# Event log analysis and optional purge
# =========================
Function Analyze-EventLogs {
    Log "Analyzing Windows Event Logs..."
    try {
        $Errors = Get-WinEvent -LogName Application -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {$_.LevelDisplayName -eq "Error"}
        if ($Errors) {
            Write-Host "Found Application Errors:" -ForegroundColor Red
            $Errors | Format-Table -Property TimeCreated, Message -AutoSize
        } else {
            Write-Host "No Application Errors Found." -ForegroundColor Green
        }
    } catch { Log "Event log analysis error: $_" }

    if ($Global:ClearEventLogs) {
        Write-Host "Clearing Event Logs..." -ForegroundColor Yellow
        try {
            Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log -ErrorAction SilentlyContinue }
            Log "Event Logs Cleared."
        } catch { Log "Event log clear error: $_" }
    }
    Log "Event Log Analysis Completed."
}

# =========================
# Debloat Windows Apps
# =========================

Function Debloat-Windows {
    if (-not $Global:EnableDebloat) { Log "Debloat disabled."; return }

    Log "Debloating Windows apps and features for $ProductName ..."
    try {
        # Protected apps that should never be removed
        $ProtectedApps = @(
            "windows.immersivecontrolpanel",
            "Microsoft.Edge",
            "Microsoft.Windows.ShellExperienceHost",
            "Microsoft.Windows.StartMenuExperienceHost",
            "Microsoft.WindowsStore",
            "Microsoft.WindowsCalculator",
            "Microsoft.WindowsNotepad",
            "Microsoft.Windows.Photos"
        )

        $Apps = Get-AppxPackage -AllUsers | Where-Object { $ProtectedApps -notcontains $_.Name }
        $Total = $Apps.Count
        $i = 0

        foreach ($App in $Apps) {
            $i++
            $Percent = [math]::Round(($i / $Total) * 100, 0)
            Write-Progress -Activity "Debloating Windows" -Status "Removing $($App.Name)" -PercentComplete $Percent

            try {
                Remove-AppxPackage -Package $App.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                Log "Removed: $($App.Name)"
            } catch {
                Log "Failed to remove: $($App.Name) - $_"
            }
        }

        # OS-specific tweaks
        if ($ProductName -like "*Windows 10*") {
            # Disable Cortana
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
        elseif ($ProductName -like "*Windows 11*") {
            # Targeted removals
            Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*WebExperience*" -or $_.Name -like "*MicrosoftTeams*" -or $_.Name -like "*YourPhone*" } | ForEach-Object {
                try {
                    Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                    Log "Removed: $($_.Name)"
                } catch {
                    Log "Failed to remove: $($_.Name) - $_"
                }
            }
            # Disable Transparency (Win11 UI)
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }

        # Common telemetry and background apps off
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -ErrorAction SilentlyContinue

        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Force | Out-Null
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    } catch { Log "Debloat error: $_" }

    Write-Progress -Activity "Debloating Windows" -Completed
    Log "Debloat Completed."
}

# =========================
# Network optimization (stack reset + NIC tuning)
# =========================
Function Optimize-Network {
    Log "Optimizing Network..."
    try {
        ipconfig /flushdns | Out-Null
        netsh winsock reset | Out-Null
        netsh int ip reset | Out-Null

        # TCP global settings: generally safe defaults
        netsh int tcp set global rss=enabled
        netsh int tcp set global autotuninglevel=normal
        netsh int tcp set global ecncapability=disabled

        # Chimney offload depends on NIC/driver; enable and log any issue silently
        netsh int tcp set global chimney=enabled

        Log "Network stack reset and TCP globals tuned."
    } catch { Log "Network optimization error: $_" }
}

# =========================
# Windows Update service health
# =========================
Function Check-UpdateService {
    Log "Checking Windows Update Service..."
    try {
        $WUService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        if ($WUService) {
            if ($WUService.Status -ne "Running") {
                Start-Service -Name wuauserv
                Log "Windows Update Service started."
            } else {
                Log "Windows Update Service is running."
            }
        } else {
            Log "Windows Update Service not found."
        }
    } catch { Log "Update service check error: $_" }
}

# =========================
# Scheduling (SYSTEM, Highest, 3:00AM)
# =========================
Function Schedule-Task {
    if (-not $Global:DoScheduleTask) { Log "Scheduling disabled."; return }
    Log "Scheduling Task..."
    try {
        $ScriptPath = "$PSScriptRoot\AutomatedSystemHealthTool.ps1"
        $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$ScriptPath`""
        $Trigger = New-ScheduledTaskTrigger -Daily -At "3:00AM"
        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
        Register-ScheduledTask -TaskName "AutomatedSystemHealthCheck" -Action $Action -Trigger $Trigger -Principal $Principal -Force
        Log "Task Scheduled for Daily Execution with highest privileges."
    } catch { Log "Scheduling error: $_" }
}

# =========================
# Main execution
# =========================
try {
    Log "Script Execution Started."
    Check-SystemHealth
    Run-SecurityScans
    Optimize-System
    Troubleshoot-Issues
    Check-DiskIntegrity
    Debloat-Windows
    Optimize-Network
    Check-UpdateService
    Check-WindowsUpdates
    Audit-Software
    Compare-PerformanceBaseline
    Backup-UserData
    Analyze-EventLogs
    Schedule-Task
    Log "Script Execution Completed Successfully."
    Write-Host "All tasks completed. Log: $LogFile" -ForegroundColor Green
} catch {
    Log "Unhandled error: $_"
    Write-Host "An error occurred: $_" -ForegroundColor Red
}
