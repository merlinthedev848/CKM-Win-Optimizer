# =========================
# Setup and logging
# =========================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 > $null

# Define a global bar character (ASCII fallback)
$Global:BarChar = "#"

$LogFolder = "$PSScriptRoot\Logs"
if (!(Test-Path -Path $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder | Out-Null }
$LogFile = "$LogFolder\HealthCheckLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Global counters for summary
$Global:RepairCount   = 0
$Global:RemovedCount  = 0
$Global:SkippedCount  = 0
$Global:ErrorCount    = 0
$Global:UpdateCount   = 0
$Global:BackupStatus  = "Not Run"
$Global:AuditCount    = 0

# Buffer file for enhanced log
$Global:LogBuffer = "$env:TEMP\CKMWinFixBuffer.log"
if (Test-Path $Global:LogBuffer) { Remove-Item $Global:LogBuffer -Force }

# Logging function (writes to buffer + console)
Function Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "$Timestamp : $Message"
    Add-Content -Path $Global:LogBuffer -Value $Entry
    Write-Host $Entry
}

# Section runner with skip option
Function Invoke-Section {
    param(
        [string]$SectionName,
        [scriptblock]$Action
    )

    $response = Read-Host "Press [Space] + Enter to skip $SectionName, or just Enter to run"
    if ($response -match '^\s+$') {
        Log "Skipped section: $SectionName"
        Write-Host "=== Skipped $SectionName ===" -ForegroundColor Cyan
    } else {
        Log "Running section: $SectionName"
        Write-Host "=== Running $SectionName ===" -ForegroundColor Yellow
        & $Action
    }
}

# =========================
# Feature toggles
# =========================
$Global:EnableDebloat       = $true
$Global:EnableFullScan      = $false
$Global:EnableChkDsk        = $true
$Global:ClearEventLogs      = $false
$Global:DoScheduleTask      = $true
$Global:EnableDriverUpdate  = $true
$Global:EnableSoftwareUpdate= $true
$Global:FixPermissions      = $true

# =========================
# Detect OS version
# =========================
$ProductReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$ProductName = $ProductReg.ProductName
$EditionID   = $ProductReg.EditionID
$ReleaseId   = $ProductReg.ReleaseId
$DisplayOS   = "$ProductName ($EditionID, Release $ReleaseId)"

Log "Detected OS: $DisplayOS"
# =========================
# Health monitoring
# =========================
Function Check-SystemHealth {
    Log "Starting System Health Check..."
    Write-Host "=== System Health Check ===" -ForegroundColor Yellow

    try {
        $CPU = Get-WmiObject Win32_Processor -Verbose
        $RAM = Get-WmiObject Win32_OperatingSystem -Verbose
        $Disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -Verbose

        $Results = @(
            [PSCustomObject]@{ Metric="CPU"; Value="$($CPU.LoadPercentage)%"; Status="OK" },
            [PSCustomObject]@{ Metric="RAM"; Value="$([math]::Round(($RAM.TotalVisibleMemorySize - $RAM.FreePhysicalMemory)/1GB)) GB used"; Status="OK" },
            [PSCustomObject]@{ Metric="Disk"; Value="$([math]::Round($Disk.FreeSpace/1GB)) GB free"; Status="OK" }
        )

        $Results | Format-Table -AutoSize
        $Results | Out-String | Add-Content -Path $LogFile

        Write-Host "`n=== Health Visual ===" -ForegroundColor Magenta
        Add-Content -Path $LogFile -Value "`n=== Health Visual ==="
        foreach ($Result in $Results) {
            $Bars = if ($Result.Metric -eq "CPU") { [math]::Round($CPU.LoadPercentage/5) }
                    elseif ($Result.Metric -eq "RAM") { [math]::Round(($RAM.TotalVisibleMemorySize - $RAM.FreePhysicalMemory)/100000) }
                    else { [math]::Round($Disk.FreeSpace/1GB/10) }
            $BarString = ($Global:BarChar * $Bars)
            $Line = ("{0,-10} {1,-20} | {2}" -f $Result.Metric, $Result.Value, $BarString)
            Write-Host $Line -ForegroundColor Cyan
            Add-Content -Path $LogFile -Value $Line
        }
    } catch {
        Log "System Health error: $($_.Exception.Message)"
    }

    Log "System Health Check Completed."
}
# =========================
# Fix Permissions (Scoped)
# =========================
Function Fix-SystemPermissions {
    if (-not $Global:FixPermissions) { Log "Permission repair disabled."; return }

    Log "Resetting user-level permissions and registry defaults..."
    Write-Host "=== Resetting File and Registry Permissions (Scoped) ===" -ForegroundColor Yellow

    try {
        # Reset ACLs only on user profile and ProgramData
        icacls "$env:USERPROFILE" /reset /t /c /q 2>$null
        icacls "C:\ProgramData" /reset /t /c /q 2>$null

        # Refresh registry & security policy defaults
        secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose 2>$null

        Log "User-level permissions and registry defaults reset."
    } catch {
        Log "Permission repair error: $($_.Exception.Message)"
    }

    Log "Permission repair completed."
}

# =========================
# Optimization tasks (cleanup, startup, visuals, power)
# =========================
Function Optimize-System {
    Log "Starting System Optimization..."

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

    Write-Host "Disabling non-Microsoft startup items..." -ForegroundColor Yellow
    try {
        Get-CimInstance -Namespace "root\cimv2" -Class Win32_StartupCommand | Where-Object { $_.Command -notlike "*Windows*" } | ForEach-Object {
            Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $_.Name -ErrorAction SilentlyContinue
            Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $_.Name -ErrorAction SilentlyContinue
        }
    } catch { Log "Startup cleanup error: $_" }

    Write-Host "Optimizing visual effects..." -ForegroundColor Yellow
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -ErrorAction SilentlyContinue
    } catch { Log "Visual effects tweak error: $_" }

    Write-Host "Setting Power Plan to High Performance..." -ForegroundColor Yellow
    try { powercfg -setactive SCHEME_MIN } catch { Log "Power plan error: $_" }

    Log "Optimization Completed."
}
# =========================
# Automated troubleshooting (SFC, DISM, DNS)
# =========================
Function Troubleshoot-Issues {
    Log "Starting Troubleshooting..."

    Write-Host "=== Running System File Checker (SFC /scannow) ===" -ForegroundColor Yellow
    $StartTime = Get-Date
    try {
        cmd /c "sfc /scannow"
        $EndTime = Get-Date
        $Duration = $EndTime - $StartTime
        Write-Host "SFC completed in $($Duration.Minutes)m $($Duration.Seconds)s" -ForegroundColor Green
        Log "SFC completed in $($Duration.Minutes)m $($Duration.Seconds)s."
    } catch { Log "SFC error: $_" }

    Write-Host "=== Running DISM /RestoreHealth ===" -ForegroundColor Yellow
    $StartTime = Get-Date
    try {
        cmd /c "DISM /Online /Cleanup-Image /RestoreHealth"
        $EndTime = Get-Date
        $Duration = $EndTime - $StartTime
        Write-Host "DISM completed in $($Duration.Minutes)m $($Duration.Seconds)s" -ForegroundColor Green
        Log "DISM completed in $($Duration.Minutes)m $($Duration.Seconds)s."
    } catch { Log "DISM error: $_" }

    Write-Host "=== Flushing DNS Cache ===" -ForegroundColor Yellow
    try { ipconfig /flushdns | Out-Host; Log "DNS cache flushed." } catch { Log "DNS flush error: $_" }

    Log "Troubleshooting Completed."
}
# =========================
# Storage Optimization
# =========================
Function Optimize-Storage {
    Log "Starting Storage Optimization..."
    Write-Host "=== Detecting Storage Devices ===" -ForegroundColor Yellow
    try {
        $Disks = Get-PhysicalDisk -Verbose
        foreach ($Disk in $Disks) {
            Write-Host "Disk: $($Disk.FriendlyName)" -ForegroundColor Cyan
            Write-Host "Media Type: $($Disk.MediaType)" -ForegroundColor Green
            Log "Detected disk: $($Disk.FriendlyName) [$($Disk.MediaType)]"

            if ($Disk.MediaType -eq "HDD") {
                Write-Host "Running defrag on HDD..." -ForegroundColor Yellow
                Optimize-Volume -DriveLetter $Disk.DeviceID -Defrag -Verbose
                Log "Defrag completed on $($Disk.FriendlyName)"
            }
            elseif ($Disk.MediaType -eq "SSD") {
                Write-Host "Running TRIM optimization on SSD..." -ForegroundColor Yellow
                Optimize-Volume -DriveLetter $Disk.DeviceID -ReTrim -Verbose
                Log "TRIM optimization completed on $($Disk.FriendlyName)"
            }
            else {
                Write-Host "Skipping unknown media type: $($Disk.MediaType)" -ForegroundColor Yellow
                Log "Skipped disk $($Disk.FriendlyName) (unknown type)"
            }
        }

        Write-Host "`n=== Storage Visual ===" -ForegroundColor Magenta
        Add-Content -Path $LogFile -Value "`n=== Storage Visual ==="
        foreach ($Disk in $Disks) {
            $Bars = if ($Disk.MediaType -eq "HDD") { 20 }
                    elseif ($Disk.MediaType -eq "SSD") { 30 }
                    else { 10 }
            $BarString = ($Global:BarChar * $Bars)
            $Line = ("{0,-20} {1,-10} | {2}" -f $Disk.FriendlyName, $Disk.MediaType, $BarString)
            Write-Host $Line -ForegroundColor Cyan
            Add-Content -Path $LogFile -Value $Line
        }
    } catch {
        Log "Storage optimization error: $($_.Exception.Message)"
        Write-Host "Error during storage optimization: $($_.Exception.Message)" -ForegroundColor Red
    }

    Log "Storage Optimization Completed."
    Write-Host "=== Storage Optimization Completed ===" -ForegroundColor Green
}
# =========================
# Disk Integrity
# =========================
Function Check-DiskIntegrity {
    Log "Starting Disk Integrity Check..."
    Write-Host "=== Disk Integrity ===" -ForegroundColor Yellow

    try {
        $Disks = Get-PhysicalDisk -Verbose
        $Results = $Disks | Select FriendlyName, OperationalStatus, HealthStatus

        $Results | Format-Table -AutoSize
        $Results | Out-String | Add-Content -Path $LogFile

        Write-Host "`n=== Disk Visual ===" -ForegroundColor Magenta
        Add-Content -Path $LogFile -Value "`n=== Disk Visual ==="
        foreach ($Disk in $Results) {
            $BarString = if ($Disk.HealthStatus -eq "Healthy") { ($Global:BarChar * 10) } else { "## ERROR ##" }
            $Line = ("{0,-20} {1,-15} {2,-10} | {3}" -f $Disk.FriendlyName, $Disk.OperationalStatus, $Disk.HealthStatus, $BarString)
            Write-Host $Line -ForegroundColor Cyan
            Add-Content -Path $LogFile -Value $Line
        }
    } catch {
        Log "Disk Integrity error: $($_.Exception.Message)"
    }

    Log "Disk Integrity Check Completed."
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
Function Run-SecurityScans {
    Log "Starting Security Scans..."

    $MpCmd = "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"
    $Exe = Get-Item $MpCmd -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($Exe) {
        Write-Host "=== Updating Windows Defender Signatures (CLI) ===" -ForegroundColor Yellow
        try { Start-Process $Exe.FullName -ArgumentList "-SignatureUpdate" -Wait; Log "Defender signatures updated via CLI." }
        catch { Log "Defender signature update error: $_" }

        Write-Host "=== Running Windows Defender Scan (CLI) ===" -ForegroundColor Yellow
        try {
            if ($Global:EnableFullScan) {
                Start-Process $Exe.FullName -ArgumentList "-Scan -ScanType 2" -Wait
                Log "Defender Full Scan triggered via CLI."
            } else {
                Start-Process $Exe.FullName -ArgumentList "-Scan -ScanType 1" -Wait
                Log "Defender Quick Scan triggered via CLI."
            }
        } catch { Log "Defender CLI scan error: $_" }
    } else {
        Log "Windows Defender CLI not found. Skipping Defender scan."
    }

    Write-Host "Checking manual-start services currently running..." -ForegroundColor Yellow
    try {
        Get-Service | Where-Object { $_.StartType -eq "Manual" -and $_.Status -eq "Running" } | Format-Table -AutoSize
    } catch { Log "Service audit error: $_" }

    Log "Security Scans Completed."
}
# =========================
# Debloat Windows Apps + Telemetry Removal
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
            "Microsoft.Windows.Photos",
            "Microsoft.AAD.BrokerPlugin",
            "Microsoft.Windows.Search",
            "Microsoft.Copilot",
            "MicrosoftTeams",
            "MicrosoftWindows.Client.WebExperience",
            "Microsoft.XboxApp",
            "Microsoft.XboxGamingOverlay",
            "Microsoft.XboxIdentityProvider"
        )

        # Curated safe-to-remove apps
        $DebloatTargets = @(
            "Microsoft.3DBuilder",
            "Microsoft.MSPaint",
            "Microsoft.Microsoft3DViewer",
            "Microsoft.SkypeApp",
            "Microsoft.ZuneMusic",
            "Microsoft.ZuneVideo",
            "Microsoft.GetHelp",
            "Microsoft.Getstarted",
            "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.People",
            "Microsoft.OneConnect",
            "Microsoft.MixedReality.Portal",
            "Microsoft.YourPhone",
            "Microsoft.MicrosoftOfficeHub"
        )

        foreach ($Target in $DebloatTargets) {
            $App = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $Target }
            if ($App) {
                $friendlyName = if ($App.DisplayName) { $App.DisplayName } else { $App.Name }
                $response = Read-Host "Do you want to remove $friendlyName? (Y/N)"
                if ($response -match '^[Yy]$') {
                    try {
                        Remove-AppxPackage -Package $App.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                        if ($?) { Log "Removed: $friendlyName" } else { Log "Skipped: $friendlyName" }
                    } catch { Log "Skipped (error): $friendlyName" }
                } else {
                    Log "User chose to keep: $friendlyName"
                }
            } else {
                Log "Not present: $Target"
            }
        }

        foreach ($App in $ProtectedApps) {
            Log "Skipped (protected): $App"
        }

        # Telemetry disable remains automatic
        Log "Disabling telemetry via registry..."
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -ErrorAction SilentlyContinue

        $TelemetryServices = @("DiagTrack","dmwappushservice","WerSvc","PcaSvc")
        foreach ($svc in $TelemetryServices) {
            try {
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
                Log "Disabled telemetry service: $svc"
            } catch { Log "Skipped (protected or not present): $svc" }
        }
    } catch {
        Log "Debloat error: $($_.Exception.Message)"
    }

    Write-Progress -Activity "Debloating Windows" -Completed
    Log "Debloat Completed."
}

# =========================
# Debloat Unused Apps
# =========================
Function Audit-InstalledSoftware {
    param(
        [switch]$AutoRemoveUnused,   # If set, removes unused apps without prompting
        [int]$Months = 6             # Default cutoff = 6 months
    )

    Log "Auditing installed software for unused programs (>$Months months)..."

    $Cutoff = (Get-Date).AddMonths(-$Months)

    try {
        $Software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName } |
                    Sort-Object DisplayName

        foreach ($App in $Software) {
            $friendlyName = $App.DisplayName
            $lastUsed = $App.InstallDate

            # Convert InstallDate if present (format: YYYYMMDD)
            if ($lastUsed -and $lastUsed -match '^\d{8}$') {
                $parsedDate = [datetime]::ParseExact($lastUsed, 'yyyyMMdd', $null)
            } else {
                $parsedDate = $null
            }

            if ($parsedDate -and $parsedDate -lt $Cutoff) {
                if ($AutoRemoveUnused) {
                    # Silent removal
                    try {
                        $UninstallString = $App.UninstallString
                        if ($UninstallString) {
                            Start-Process -FilePath "cmd.exe" -ArgumentList "/c $UninstallString" -Wait
                            Log "Auto-removed unused software: $friendlyName"
                        } else {
                            Log "No uninstall string for: $friendlyName"
                        }
                    } catch {
                        Log "Error uninstalling $friendlyName: $_"
                    }
                } else {
                    # Interactive prompt
                    $response = Read-Host "Remove $friendlyName (last used/installed $parsedDate)? (Y/N)"
                    if ($response -match '^[Yy]$') {
                        try {
                            $UninstallString = $App.UninstallString
                            if ($UninstallString) {
                                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $UninstallString" -Wait
                                Log "Removed unused software: $friendlyName"
                            } else {
                                Log "No uninstall string for: $friendlyName"
                            }
                        } catch {
                            Log "Error uninstalling $friendlyName: $_"
                        }
                    } else {
                        Log "User chose to keep: $friendlyName"
                    }
                }
            } else {
                Log "Kept: $friendlyName (recently used or no usage data)"
            }
        }
    } catch {
        Log "Software audit error: $($_.Exception.Message)"
    }

    Log "Software audit completed."
}


# =========================
# Windows updates (PSWindowsUpdate or USOClient fallback)
# =========================
Function Check-WindowsUpdates {
    Log "Checking for Windows Updates..."
    Write-Host "Checking for Windows Updates..." -ForegroundColor Yellow
    if (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue) {
        try {
            Get-WindowsUpdate -Install -AcceptAll -AutoReboot | Out-Null
            Log "Windows Updates installed via PSWindowsUpdate."
        } catch {
            Log "Error running Get-WindowsUpdate: $_"
            Write-Host "An error occurred while checking updates: $_" -ForegroundColor Red
        }
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
# Driver and Software Auto update
# =========================
Function Update-System {
    Log "Starting driver and software updates..."
    Write-Host "=== Updating Drivers and Software ===" -ForegroundColor Yellow

    try {
        Write-Host "Checking for driver updates..." -ForegroundColor Cyan
        Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot | Out-Host
        Log "Driver updates applied."

        Write-Host "Updating installed applications..." -ForegroundColor Cyan
        winget upgrade --all --silent | Out-Host
        Log "Software updates applied."
    } catch {
        Log "Update error: $_"
    }

    Log "Driver and software updates completed."
}
# =========================
# Network optimization
# =========================
Function Optimize-NetworkAuto {
    Log "Starting Auto Network Optimization..."
    Write-Host "=== Detecting Network Adapter Capability ===" -ForegroundColor Yellow

    $Results = @()

    try {
        $Adapters = Get-CimInstance Win32_NetworkAdapter -Verbose | Where-Object { $_.NetEnabled -eq $true }

        foreach ($Adapter in $Adapters) {
            $NegotiatedMbps = [math]::Round($Adapter.Speed / 1e6)
            $Desc = $Adapter.Description

            $Result = [PSCustomObject]@{
                Adapter     = $Adapter.Name
                Description = $Desc
                SpeedMbps   = $NegotiatedMbps
            }
            $Results += $Result

            Log "Adapter: $($Adapter.Name) [$Desc] Speed: $NegotiatedMbps Mbps"
        }

        Write-Host "`n=== Speedtest Visual ===" -ForegroundColor Magenta
        Add-Content -Path $LogFile -Value "`n=== Speedtest Visual ==="
        foreach ($Result in $Results) {
            $Bars = [math]::Round($Result.SpeedMbps / 100)
            $BarString = ($Global:BarChar * $Bars)
            $Line = ("{0,-20} {1,6} Mbps | {2}" -f $Result.Adapter, $Result.SpeedMbps, $BarString)
            Write-Host $Line -ForegroundColor Cyan
            Add-Content -Path $LogFile -Value $Line
        }
    } catch {
        Log "Network optimization error: $($_.Exception.Message)"
    }

    Log "Network Optimization Completed."
}
# =========================
# Performance Baseline
# =========================
Function Compare-PerformanceBaseline {
    Log "Starting Performance Baseline Comparison..."
    Write-Host "=== Performance Baseline ===" -ForegroundColor Yellow

    try {
        $Perf = Get-Counter '\Processor(_Total)\% Processor Time','\Memory\Available MBytes','\PhysicalDisk(_Total)\Avg. Disk Queue Length' -Verbose
        $Results = @(
            [PSCustomObject]@{ Metric="CPU Usage"; Value="$([math]::Round($Perf.CounterSamples[0].CookedValue))%" },
            [PSCustomObject]@{ Metric="Available RAM"; Value="$([math]::Round($Perf.CounterSamples[1].CookedValue)) MB" },
            [PSCustomObject]@{ Metric="Disk Queue"; Value="$([math]::Round($Perf.CounterSamples[2].CookedValue,2))" }
        )

        $Results | Format-Table -AutoSize
        $Results | Out-String | Add-Content -Path $LogFile

        Write-Host "`n=== Performance Visual ===" -ForegroundColor Magenta
        Add-Content -Path $LogFile -Value "`n=== Performance Visual ==="
        foreach ($Result in $Results) {
            $Bars = if ($Result.Metric -eq "CPU Usage") { [math]::Round(($Perf.CounterSamples[0].CookedValue)/5) }
                    elseif ($Result.Metric -eq "Available RAM") { [math]::Round(($Perf.CounterSamples[1].CookedValue)/100) }
                    else { [math]::Round(($Perf.CounterSamples[2].CookedValue)*10) }
            $BarString = ($Global:BarChar * $Bars)
            $Line = ("{0,-15} {1,-15} | {2}" -f $Result.Metric, $Result.Value, $BarString)
            Write-Host $Line -ForegroundColor Cyan
            Add-Content -Path $LogFile -Value $Line
        }
    } catch {
        Log "Performance Baseline error: $($_.Exception.Message)"
    }

    Log "Performance Baseline Completed."
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
    } catch {
        Log "Backup error: $_"
        Write-Host "Backup encountered an error: $_" -ForegroundColor Red
    }
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
# Task Scheduling
# =========================
Function Schedule-Task {
    if (-not $Global:DoScheduleTask) { Log "Task scheduling disabled."; return }

    Log "Configuring scheduled task for weekly optimization..."
    Write-Host "=== Scheduling Weekly Optimization Task ===" -ForegroundColor Yellow

    try {
        $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File `"$PSScriptRoot\CKMWinFix.ps1`""
        $Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal

        Register-ScheduledTask -TaskName "CKMWinFix" -InputObject $Task -Force
        Log "Scheduled task 'CKMWinFix' created to run weekly."
    } catch {
        Log "Task scheduling error: $($_.Exception.Message)"
        Write-Host "Error creating scheduled task: $($_.Exception.Message)" -ForegroundColor Red
    }

    Log "Task Scheduling Completed."
}
# =========================
# Final Summary Writer
# =========================
Function Write-FinalSummary {
    try {
        $summary = @()
        $summary += "=== CKMWinFix Summary ==="
        $summary += "System Health Checks: Completed"
        $summary += "Repairs Applied: $Global:RepairCount"
        $summary += "Apps Removed: $Global:RemovedCount"
        $summary += "Apps Skipped: $Global:SkippedCount"
        $summary += "Errors: $Global:ErrorCount"
        $summary += "Updates Applied: $Global:UpdateCount"
        $summary += "Backup Status: $Global:BackupStatus"
        $summary += "Audit Findings: $Global:AuditCount"
        $summary += "==========================="

        # Write summary first
        $summary | Out-File -FilePath $LogFile -Encoding UTF8

        # Append enhanced log history
        Add-Content -Path $LogFile -Value "`n=== Enhanced Log ===`n"
        Get-Content $Global:LogBuffer | Add-Content -Path $LogFile

        Write-Host "Final summary and enhanced log written to: $LogFile" -ForegroundColor Cyan
    } catch {
        Write-Host "Error writing final summary: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# =========================
# Main Execution
# =========================
try {
    Log "Script Execution Started."
    Write-Host "=== CKMWinFix Script Execution Started ===" -ForegroundColor Yellow

    Invoke-Section "Baseline and prerequisites" {
        Check-SystemHealth
        Ensure-Defender
    }

    Invoke-Section "Core repairs and cleanup" {
        Troubleshoot-Issues       # SFC, DISM, DNS
        Fix-SystemPermissions     # Reset ACLs and registry defaults
        Optimize-System           # Temp/cache cleanup, startup, visuals, power plan
    }

    Invoke-Section "Storage and integrity" {
        Optimize-Storage          # Defrag HDDs, TRIM SSDs
        Check-DiskIntegrity       # Health status of physical disks
    }

    Invoke-Section "Security and debloat" {
        Run-SecurityScans         # Defender signature update + scan
        Debloat-Windows           # Curated removals + telemetry off
        Audit-InstalledSoftware   # Interactive removal of unused programs (>6 months)
    }

    Invoke-Section "Updates and performance" {
        Check-WindowsUpdates      # OS updates (PSWindowsUpdate/USOClient)
        Update-System             # Drivers + Winget apps
        Optimize-NetworkAuto      # Adapter detection + speed visuals
        Compare-PerformanceBaseline
    }

    Invoke-Section "Backup and audit" {
        Backup-UserData
        Analyze-EventLogs
        Audit-Software
    }

    Invoke-Section "Scheduling and summary" {
        Schedule-Task
        Write-FinalSummary
    }

    Log "Script Execution Completed Successfully."
    Write-Host "=== CKMWinFix Script Execution Completed ===" -ForegroundColor Green
    Write-Host "Log file saved to: $LogFile" -ForegroundColor Cyan
} catch {
    $Global:ErrorCount++
    Log "Unhandled error: $($_.Exception.Message)"
    Write-Host "An unhandled error occurred: $($_.Exception.Message)" -ForegroundColor Red
}
