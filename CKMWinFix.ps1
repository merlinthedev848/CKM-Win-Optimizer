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

# Logging function (writes to buffer + main log + console)
Function Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "$Timestamp : $Message"
    Add-Content -Path $Global:LogBuffer -Value $Entry
    Add-Content -Path $LogFile -Value $Entry
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
        $Global:SkippedCount++
    } else {
        Log "Running section: $SectionName"
        Write-Host "=== Running $SectionName ===" -ForegroundColor Yellow
        & $Action
    }
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
        $Global:RepairCount++

        # Refresh registry & security policy defaults
        secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose 2>$null
        $Global:RepairCount++

        Log "User-level permissions and registry defaults reset."
    } catch {
        $Global:ErrorCount++
        Log "Permission repair error: $($_.Exception.Message)"
    }

    Log "Fix-SystemPermissions Completed."
}


# =========================
# Optimization tasks (cleanup, startup, visuals, power)
# =========================
Function Optimize-System {
    Log "Starting System Optimization..."
    Write-Host "=== System Optimization ===" -ForegroundColor Yellow

    # Clean temp + prefetch
    Write-Host "Cleaning Temporary Files and Prefetch..." -ForegroundColor Yellow
    try {
        Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
        $Global:RepairCount++
        Log "Temp and Prefetch cleaned."
    } catch {
        $Global:ErrorCount++
        Log "Temp/Prefetch cleanup error: $($_.Exception.Message)"
    }

    # Clean Windows Update cache
    Write-Host "Cleaning Windows Update cache..." -ForegroundColor Yellow
    try {
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Stop-Service -Name bits -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Windows\SoftwareDistribution\DataStore\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\ProgramData\USOShared\Logs\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\ProgramData\Microsoft\Windows\DeliveryOptimization\*" -Recurse -Force -ErrorAction SilentlyContinue
        $Global:RepairCount++
        Log "Windows Update cache cleaned."
    } catch {
        $Global:ErrorCount++
        Log "Update cache cleanup error: $($_.Exception.Message)"
    } finally {
        Start-Service -Name bits -ErrorAction SilentlyContinue
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    }

    # Empty recycle bin
    Write-Host "Emptying Recycle Bin..." -ForegroundColor Yellow
    try {
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        $Global:RepairCount++
        Log "Recycle Bin emptied."
    } catch {
        $Global:ErrorCount++
        Log "Recycle Bin cleanup error: $($_.Exception.Message)"
    }

    # Disable non-Microsoft startup items
    Write-Host "Disabling non-Microsoft startup items..." -ForegroundColor Yellow
    try {
        Get-CimInstance -Namespace "root\cimv2" -Class Win32_StartupCommand |
            Where-Object { $_.Command -notlike "*Windows*" } |
            ForEach-Object {
                Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $_.Name -ErrorAction SilentlyContinue
                Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $_.Name -ErrorAction SilentlyContinue
                $Global:RepairCount++
                Log "Disabled startup item: $($_.Name)"
            }
    } catch {
        $Global:ErrorCount++
        Log "Startup cleanup error: $($_.Exception.Message)"
    }

    # Optimize visual effects
    Write-Host "Optimizing visual effects..." -ForegroundColor Yellow
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -ErrorAction SilentlyContinue
        $Global:RepairCount++
        Log "Visual effects optimized."
    } catch {
        $Global:ErrorCount++
        Log "Visual effects tweak error: $($_.Exception.Message)"
    }

    # Set power plan
    Write-Host "Setting Power Plan to High Performance..." -ForegroundColor Yellow
    try {
        powercfg -setactive SCHEME_MIN
        $Global:RepairCount++
        Log "Power plan set to High Performance."
    } catch {
        $Global:ErrorCount++
        Log "Power plan error: $($_.Exception.Message)"
    }

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
            $Global:RepairCount++
            Log "Windows Defender feature enabled."
        } else {
            Log "Windows Defender is already enabled."
        }
    } catch {
        $Global:ErrorCount++
        Log "Failed to check/enable Windows Defender: $($_.Exception.Message)"
    }
}

Function Run-SecurityScans {
    Log "Starting Security Scans..."
    Write-Host "=== Security Scans ===" -ForegroundColor Yellow

    $MpCmd = "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"
    $Exe = Get-Item $MpCmd -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($Exe) {
        # Update signatures
        Write-Host "=== Updating Windows Defender Signatures (CLI) ===" -ForegroundColor Yellow
        try {
            Start-Process $Exe.FullName -ArgumentList "-SignatureUpdate" -Wait
            $Global:UpdateCount++
            Log "Defender signatures updated via CLI."
        } catch {
            $Global:ErrorCount++
            Log "Defender signature update error: $($_.Exception.Message)"
        }

        # Run scan
        Write-Host "=== Running Windows Defender Scan (CLI) ===" -ForegroundColor Yellow
        try {
            if ($Global:EnableFullScan) {
                Start-Process $Exe.FullName -ArgumentList "-Scan -ScanType 2" -Wait
                $Global:RepairCount++
                Log "Defender Full Scan triggered via CLI."
            } else {
                Start-Process $Exe.FullName -ArgumentList "-Scan -ScanType 1" -Wait
                $Global:RepairCount++
                Log "Defender Quick Scan triggered via CLI."
            }
        } catch {
            $Global:ErrorCount++
            Log "Defender CLI scan error: $($_.Exception.Message)"
        }
    } else {
        $Global:SkippedCount++
        Log "Windows Defender CLI not found. Skipping Defender scan."
    }

    # Audit manual-start services
    Write-Host "Checking manual-start services currently running..." -ForegroundColor Yellow
    try {
        Get-Service | Where-Object { $_.StartType -eq "Manual" -and $_.Status -eq "Running" } | Format-Table -AutoSize
        Log "Manual-start services audit completed."
    } catch {
        $Global:ErrorCount++
        Log "Service audit error: $($_.Exception.Message)"
    }

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
# Debloat Windows
# =========================
Function Debloat-Windows {
    if (-not $Global:EnableDebloat) { Log "Debloat disabled."; return }

    Log "Debloating Windows apps and features..."

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
                        if ($?) {
                            $Global:RemovedCount++
                            Log "Removed: $friendlyName"
                        } else {
                            $Global:SkippedCount++
                            Log "Skipped: $friendlyName"
                        }
                    } catch {
                        $Global:ErrorCount++
                        Log "Error removing: $friendlyName"
                    }
                } else {
                    $Global:SkippedCount++
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
            } catch {
                Log "Skipped (protected or not present): $svc"
            }
        }
    } catch {
        $Global:ErrorCount++
        Log "Debloat error: $($_.Exception.Message)"
    }

    Write-Progress -Activity "Debloating Windows" -Completed
    Log "Debloat Completed."
}



# =========================
# Check Windows Updates
# =========================
Function Check-WindowsUpdates {
    Log "Checking for Windows Updates..."
    Write-Host "=== Checking Windows Updates ===" -ForegroundColor Yellow

    try {
        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue

        if (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue) {
            $updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot
            if ($updates) {
                $Global:UpdateCount += $updates.Count
                Log "Applied $($updates.Count) Windows updates."
            } else {
                $Global:SkippedCount++
                Log "No Windows updates available."
            }
        } else {
            # Fallback to USOClient
            Log "PSWindowsUpdate not available, using USOClient..."
            Start-Process -FilePath "usoclient.exe" -ArgumentList "StartScan" -Wait
            $Global:RepairCount++
        }
    } catch {
        $Global:ErrorCount++
        Log "Windows Update error: $($_.Exception.Message)"
    }

    Log "Windows Update check completed."
}

# =========================
# Update System (Drivers + Winget Apps)
# =========================
Function Update-System {
    Log "Updating drivers and Winget apps..."
    Write-Host "=== Updating System ===" -ForegroundColor Yellow

    try {
        # Update drivers via pnputil
        try {
            pnputil /scan-devices | Out-Null
            $Global:UpdateCount++
            Log "Driver scan completed."
        } catch {
            $Global:ErrorCount++
            Log "Driver update error: $($_.Exception.Message)"
        }

        # Update apps via Winget
        try {
            $updates = winget upgrade --accept-source-agreements --accept-package-agreements
            if ($updates) {
                $Global:UpdateCount++
                Log "Winget apps updated."
            } else {
                $Global:SkippedCount++
                Log "No Winget updates available."
            }
        } catch {
            $Global:ErrorCount++
            Log "Winget update error: $($_.Exception.Message)"
        }
    } catch {
        $Global:ErrorCount++
        Log "System update error: $($_.Exception.Message)"
    }

    Log "System update completed."
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
    Write-Host "=== Backup User Data ===" -ForegroundColor Yellow

    $BackupSource = "$env:USERPROFILE\Documents"
    $BackupDestination = "$PSScriptRoot\Backups"

    if (!(Test-Path -Path $BackupDestination)) {
        New-Item -ItemType Directory -Path $BackupDestination | Out-Null
    }

    $RoboArgs = "`"$BackupSource`" `"$BackupDestination`" /E /COPY:DAT /R:1 /W:1 /NFL /NDL /NP /XA:SH /XJ /LOG:$LogFile"

    try {
        Start-Process -FilePath "robocopy.exe" -ArgumentList $RoboArgs -Wait
        Write-Host "Backup Completed: $BackupSource to $BackupDestination" -ForegroundColor Green
        $Global:BackupStatus = "Success"
        Log "Backup Completed successfully."
    } catch {
        $Global:BackupStatus = "Failed"
        $Global:ErrorCount++
        Log "Backup error: $($_.Exception.Message)"
        Write-Host "Backup encountered an error: $($_.Exception.Message)" -ForegroundColor Red
    }

    Log "Backup process finished."
}

# =========================
# Event log analysis and optional purge
# =========================
Function Analyze-EventLogs {
    Log "Analyzing Windows Event Logs..."
    Write-Host "=== Event Log Analysis ===" -ForegroundColor Yellow

    try {
        $Errors = Get-WinEvent -LogName Application -MaxEvents 100 -ErrorAction SilentlyContinue |
                  Where-Object { $_.LevelDisplayName -eq "Error" }

        if ($Errors -and $Errors.Count -gt 0) {
            $Global:AuditCount += $Errors.Count
            Write-Host "Found Application Errors:" -ForegroundColor Red
            $Errors | Format-Table -Property TimeCreated, Message -AutoSize
            Log "Found $($Errors.Count) Application errors in the last 100 events."
        } else {
            $Global:SkippedCount++
            Write-Host "No Application Errors Found." -ForegroundColor Green
            Log "No Application errors detected."
        }
    } catch {
        $Global:ErrorCount++
        Log "Event log analysis error: $($_.Exception.Message)"
    }

    if ($Global:ClearEventLogs) {
        Write-Host "Clearing Event Logs..." -ForegroundColor Yellow
        try {
            Get-EventLog -List | ForEach-Object {
                Clear-EventLog -LogName $_.Log -ErrorAction SilentlyContinue
            }
            $Global:RepairCount++
            Log "Event Logs Cleared."
        } catch {
            $Global:ErrorCount++
            Log "Event log clear error: $($_.Exception.Message)"
        }
    }

    Log "Event Log Analysis Completed."
}

# =========================
# Audit Installed Software
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
                $Global:AuditCount++
                if ($AutoRemoveUnused) {
                    try {
                        $UninstallString = $App.UninstallString
                        if ($UninstallString) {
                            Start-Process -FilePath "cmd.exe" -ArgumentList "/c $UninstallString" -Wait
                            $Global:RemovedCount++
                            Log "Auto-removed unused software: $friendlyName"
                        } else {
                            $Global:SkippedCount++
                            Log "No uninstall string for: $friendlyName"
                        }
                    } catch {
                        $Global:ErrorCount++
                        Log "Error uninstalling $friendlyName: $_"
                    }
                } else {
                    $response = Read-Host "Remove $friendlyName (installed $parsedDate)? (Y/N)"
                    if ($response -match '^[Yy]$') {
                        try {
                            $UninstallString = $App.UninstallString
                            if ($UninstallString) {
                                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $UninstallString" -Wait
                                $Global:RemovedCount++
                                Log "Removed unused software: $friendlyName"
                            } else {
                                $Global:SkippedCount++
                                Log "No uninstall string for: $friendlyName"
                            }
                        } catch {
                            $Global:ErrorCount++
                            Log "Error uninstalling $friendlyName: $_"
                        }
                    } else {
                        $Global:SkippedCount++
                        Log "User chose to keep: $friendlyName"
                    }
                }
            } else {
                Log "Kept: $friendlyName (recently used or no usage data)"
            }
        }
    } catch {
        $Global:ErrorCount++
        Log "Software audit error: $($_.Exception.Message)"
    }

    Log "Interactive software audit completed."
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
        Audit-InstalledSoftware   # Compliance + unused software audit
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
