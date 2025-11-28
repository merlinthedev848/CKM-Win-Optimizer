# =========================
# Setup and logging
# =========================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 > $null

# Define a global bar character (ASCII fallback)
$Global:BarChar = "#"

# Ensure log folder exists
$LogFolder = "$PSScriptRoot\Logs"
if (!(Test-Path -Path $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder | Out-Null
}
$LogFile = "$LogFolder\HealthCheckLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Global counters for summary
$Global:RepairCount   = 0
$Global:RemovedCount  = 0
$Global:SkippedCount  = 0
$Global:ErrorCount    = 0
$Global:UpdateCount   = 0
$Global:BackupStatus  = "Not Run"
$Global:AuditCount    = 0

# Logging function (writes directly to file + console)
Function Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "$Timestamp : $Message"
    try {
        Add-Content -Path $LogFile -Value $Entry -ErrorAction Stop
    } catch {
        Write-Host "Failed to write to log file: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host $Entry
}

# Section runner (interactive skip)
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
        try {
            & $Action
            Log "Section '${SectionName}' completed."
        } catch {
            $Global:ErrorCount++
            Log "Error in section ${SectionName}: $($_.Exception.Message)"
            Write-Host "Error in section ${SectionName}: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}



# Basic system health check
Function Check-SystemHealth {
    Log "Running basic system health checks..."
    Write-Host "=== System Health Check ===" -ForegroundColor Yellow
    try {
        $FreeSpace = Get-PSDrive C | Select-Object -ExpandProperty Free
        Log "Free space on C: $([math]::Round($FreeSpace/1GB,2)) GB"
        $Global:AuditCount++
    } catch {
        $Global:ErrorCount++
        Log "System health check error: $($_.Exception.Message)"
    }
    Log "System health check completed."
}

# =========================
# Final Summary Writer
# =========================
Function Write-FinalSummary {
    try {
        Write-Host "`n=== CKMWinFix Summary ===" -ForegroundColor Cyan
        Write-Host "Repairs Applied: $Global:RepairCount" -ForegroundColor Green
        Write-Host "Apps Removed:   $Global:RemovedCount" -ForegroundColor Green
        Write-Host "Apps Skipped:   $Global:SkippedCount" -ForegroundColor Yellow
        Write-Host "Errors:         $Global:ErrorCount" -ForegroundColor Red
        Write-Host "Updates Applied:$Global:UpdateCount" -ForegroundColor Green
        Write-Host "Backup Status:  $Global:BackupStatus" -ForegroundColor Cyan
        Write-Host "Audit Findings: $Global:AuditCount" -ForegroundColor Magenta
        Write-Host "===========================" -ForegroundColor Cyan

        # Write summary to log file
        Add-Content -Path $LogFile -Value "`n=== CKMWinFix Summary ==="
        Add-Content -Path $LogFile -Value "Repairs Applied: $Global:RepairCount"
        Add-Content -Path $LogFile -Value "Apps Removed:   $Global:RemovedCount"
        Add-Content -Path $LogFile -Value "Apps Skipped:   $Global:SkippedCount"
        Add-Content -Path $LogFile -Value "Errors:         $Global:ErrorCount"
        Add-Content -Path $LogFile -Value "Updates Applied:$Global:UpdateCount"
        Add-Content -Path $LogFile -Value "Backup Status:  $Global:BackupStatus"
        Add-Content -Path $LogFile -Value "Audit Findings: $Global:AuditCount"
        Add-Content -Path $LogFile -Value "==========================="

        Write-Host "`nFinal summary written to: $LogFile" -ForegroundColor Cyan
    } catch {
        $Global:ErrorCount++
        Log "Error writing final summary: $($_.Exception.Message)"
        Write-Host "Error writing final summary: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# =========================
# Feature toggles
# =========================
$Global:EnableDebloat        = $true
$Global:EnableFullScan       = $false
$Global:EnableChkDsk         = $true
$Global:ClearEventLogs       = $false
$Global:DoScheduleTask       = $true
$Global:EnableDriverUpdate   = $true
$Global:EnableSoftwareUpdate = $true
$Global:FixPermissions       = $true

# =========================
# Detect OS version
# =========================
try {
    $ProductReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $ProductName = $ProductReg.ProductName
    $EditionID   = $ProductReg.EditionID
    $ReleaseId   = $ProductReg.ReleaseId
    $DisplayOS   = "$ProductName ($EditionID, Release $ReleaseId)"
    Log "Detected OS: $DisplayOS"
} catch {
    $Global:ErrorCount++
    Log "OS detection error: $($_.Exception.Message)"
}

# =========================
# Health monitoring
# =========================
Function Check-SystemHealth {
    Log "Starting System Health Check..."
    Write-Host "=== System Health Check ===" -ForegroundColor Yellow

    try {
        $CPU  = Get-WmiObject Win32_Processor -ErrorAction Stop
        $RAM  = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        $Disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop

        $Results = @(
            [PSCustomObject]@{ Metric="CPU";  Value="$($CPU.LoadPercentage)%"; Status="OK" },
            [PSCustomObject]@{ Metric="RAM";  Value="$([math]::Round(($RAM.TotalVisibleMemorySize - $RAM.FreePhysicalMemory)/1GB)) GB used"; Status="OK" },
            [PSCustomObject]@{ Metric="Disk"; Value="$([math]::Round($Disk.FreeSpace/1GB)) GB free"; Status="OK" }
        )

        $Results | Format-Table -AutoSize
        $Results | Out-String | Add-Content -Path $LogFile

        Write-Host "`n=== Health Visual ===" -ForegroundColor Magenta
        Add-Content -Path $LogFile -Value "`n=== Health Visual ==="

        foreach ($Result in $Results) {
            $Bars = switch ($Result.Metric) {
                "CPU"  { [math]::Round($CPU.LoadPercentage / 5) }
                "RAM"  { [math]::Round(($RAM.TotalVisibleMemorySize - $RAM.FreePhysicalMemory) / 100000) }
                "Disk" { [math]::Round(($Disk.FreeSpace / 1GB) / 10) }
            }
            if ($Bars -lt 1) { $Bars = 1 } # ensure at least one bar
            $BarString = ($Global:BarChar * $Bars)
            $Line = ("{0,-10} {1,-20} | {2}" -f $Result.Metric, $Result.Value, $BarString)
            Write-Host $Line -ForegroundColor Cyan
            Add-Content -Path $LogFile -Value $Line
        }

        $Global:AuditCount++
        Log "System Health Check Completed."
    } catch {
        $Global:ErrorCount++
        Log "System Health error: $($_.Exception.Message)"
        Write-Host "System Health error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# =========================
# Fix Permissions (Scoped with Progress)
# =========================
Function Fix-SystemPermissions {
    if (-not $Global:FixPermissions) {
        Log "Permission repair disabled."
        return
    }

    Log "Resetting user-level permissions and registry defaults..."
    Write-Host "=== Resetting File and Registry Permissions (Scoped) ===" -ForegroundColor Yellow

    try {
        # Step 1: Reset ACLs on user profile
        Write-Progress -Activity "Fix-SystemPermissions" -Status "Resetting ACLs on user profile..." -PercentComplete 25
        Write-Host "Resetting ACLs on $env:USERPROFILE..." -ForegroundColor Cyan
        icacls "$env:USERPROFILE" /reset /t /c /q 2>$null

        # Step 2: Reset ACLs on ProgramData
        Write-Progress -Activity "Fix-SystemPermissions" -Status "Resetting ACLs on ProgramData..." -PercentComplete 50
        Write-Host "Resetting ACLs on C:\ProgramData..." -ForegroundColor Cyan
        icacls "C:\ProgramData" /reset /t /c /q 2>$null

        $Global:RepairCount++
        Log "ACLs reset for user profile and ProgramData."

        # Step 3: Refresh registry & security policy defaults
        $DefltBase = Join-Path $env:windir "inf\defltbase.inf"
        if (Test-Path $DefltBase) {
            Write-Progress -Activity "Fix-SystemPermissions" -Status "Refreshing registry & security policy defaults..." -PercentComplete 75
            Write-Host "Refreshing registry & security policy defaults..." -ForegroundColor Cyan
            secedit /configure /cfg $DefltBase /db defltbase.sdb /verbose 2>$null

            $Global:RepairCount++
            Log "Registry and security policy defaults refreshed."
        } else {
            $Global:SkippedCount++
            Log "Skipped registry defaults reset (defltbase.inf not found)."
            Write-Host "Skipped registry defaults reset (defltbase.inf not found)." -ForegroundColor Yellow
        }

        # Step 4: Completed
        Write-Progress -Activity "Fix-SystemPermissions" -Status "Completed" -PercentComplete 100
        Log "Fix-SystemPermissions Completed."
        Write-Host "=== Fix-SystemPermissions Completed ===" -ForegroundColor Green
    } catch {
        $Global:ErrorCount++
        Log "Permission repair error: $($_.Exception.Message)"
        Write-Host "Permission repair error: $($_.Exception.Message)" -ForegroundColor Red
    }
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
        Write-Host "Temp/Prefetch cleanup error: $($_.Exception.Message)" -ForegroundColor Red
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
        Write-Host "Update cache cleanup error: $($_.Exception.Message)" -ForegroundColor Red
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
        Write-Host "Recycle Bin cleanup error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Disable non-Microsoft startup items (safer approach)
    Write-Host "Disabling non-Microsoft startup items..." -ForegroundColor Yellow
    try {
        $StartupItems = Get-CimInstance -Namespace "root\cimv2" -Class Win32_StartupCommand |
            Where-Object { $_.Command -and $_.Command -notlike "*Windows*" }

        foreach ($Item in $StartupItems) {
            try {
                Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $Item.Name -ErrorAction SilentlyContinue
                Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $Item.Name -ErrorAction SilentlyContinue
                $Global:RepairCount++
                Log "Disabled startup item: $($Item.Name)"
            } catch {
                $Global:SkippedCount++
                Log "Skipped startup item (error): $($Item.Name)"
            }
        }
    } catch {
        $Global:ErrorCount++
        Log "Startup cleanup error: $($_.Exception.Message)"
        Write-Host "Startup cleanup error: $($_.Exception.Message)" -ForegroundColor Red
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
        Write-Host "Visual effects tweak error: $($_.Exception.Message)" -ForegroundColor Red
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
        Write-Host "Power plan error: $($_.Exception.Message)" -ForegroundColor Red
    }

    Log "Optimization Completed."
    Write-Host "=== Optimization Completed ===" -ForegroundColor Green
}

# =========================
# Automated troubleshooting (SFC, DISM, DNS)
# =========================
Function Troubleshoot-Issues {
    Log "Starting Troubleshooting..."
    Write-Host "=== Automated Troubleshooting ===" -ForegroundColor Yellow

    # Run System File Checker
    Write-Host "=== Running System File Checker (SFC /scannow) ===" -ForegroundColor Yellow
    $StartTime = Get-Date
    try {
        cmd /c "sfc /scannow"
        $EndTime = Get-Date
        $Duration = $EndTime - $StartTime
        Write-Host "SFC completed in $($Duration.Minutes)m $($Duration.Seconds)s" -ForegroundColor Green
        Log "SFC completed in $($Duration.Minutes)m $($Duration.Seconds)s."
        $Global:RepairCount++
    } catch {
        $Global:ErrorCount++
        Log "SFC error: $($_.Exception.Message)"
        Write-Host "SFC error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Run DISM RestoreHealth
    Write-Host "=== Running DISM /RestoreHealth ===" -ForegroundColor Yellow
    $StartTime = Get-Date
    try {
        cmd /c "DISM /Online /Cleanup-Image /RestoreHealth"
        $EndTime = Get-Date
        $Duration = $EndTime - $StartTime
        Write-Host "DISM completed in $($Duration.Minutes)m $($Duration.Seconds)s" -ForegroundColor Green
        Log "DISM completed in $($Duration.Minutes)m $($Duration.Seconds)s."
        $Global:RepairCount++
    } catch {
        $Global:ErrorCount++
        Log "DISM error: $($_.Exception.Message)"
        Write-Host "DISM error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Flush DNS cache
    Write-Host "=== Flushing DNS Cache ===" -ForegroundColor Yellow
    try {
        ipconfig /flushdns | Out-Host
        Log "DNS cache flushed."
        $Global:RepairCount++
    } catch {
        $Global:ErrorCount++
        Log "DNS flush error: $($_.Exception.Message)"
        Write-Host "DNS flush error: $($_.Exception.Message)" -ForegroundColor Red
    }

    Log "Troubleshooting Completed."
    Write-Host "=== Troubleshooting Completed ===" -ForegroundColor Green
}

# =========================
# Storage and Integrity (Hybrid with Progress)
# =========================
Function Optimize-Storage {
    Log "Starting Storage Optimization..."
    Write-Host "=== Detecting Storage Devices ===" -ForegroundColor Yellow
    try {
        # Prefer modern cmdlet, fallback to WMI
        if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
            $disks = Get-PhysicalDisk
        } else {
            $disks = Get-WmiObject Win32_DiskDrive
        }

        if ($disks) {
            $i = 0
            foreach ($d in $disks) {
                $i++
                $percent = [math]::Round(($i / $disks.Count) * 100)
                Write-Progress -Activity "Storage Optimization" -Status "Checking $($d.FriendlyName)" -PercentComplete $percent

                $name  = if ($d.PSObject.Properties.Name -contains 'FriendlyName') { $d.FriendlyName } else { $d.Model }
                $size  = if ($d.PSObject.Properties.Name -contains 'Size') { [math]::Round($d.Size/1GB,2) } else { "Unknown" }
                $type  = if ($d.PSObject.Properties.Name -contains 'MediaType') { $d.MediaType } else { "Unknown" }

                Write-Host "Disk: $name | Size: $size GB | Type: $type" -ForegroundColor Cyan
                Log "Detected disk: $name, $size GB, $type"
            }
        } else {
            $Global:SkippedCount++
            Log "No disks detected."
            Write-Host "No disks detected." -ForegroundColor Yellow
        }
    } catch {
        $Global:ErrorCount++
        Log "Storage optimization error: $($_.Exception.Message)"
        Write-Host "Storage optimization error: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Progress -Activity "Storage Optimization" -Status "Completed" -PercentComplete 100
    Log "Storage Optimization Completed."
    Write-Host "=== Storage Optimization Completed ===" -ForegroundColor Green
}

Function Check-DiskIntegrity {
    Log "Starting Disk Integrity Check..."
    Write-Host "=== Disk Integrity ===" -ForegroundColor Yellow
    try {
        # Prefer modern cmdlet, fallback to WMI
        if (Get-Command Get-Volume -ErrorAction SilentlyContinue) {
            $volumes = Get-Volume
        } else {
            $volumes = Get-WmiObject Win32_Volume
        }

        if ($volumes) {
            $i = 0
            foreach ($v in $volumes) {
                $i++
                $percent = [math]::Round(($i / $volumes.Count) * 100)
                $label = if ($v.PSObject.Properties.Name -contains 'FileSystemLabel') { $v.FileSystemLabel } else { $v.Label }
                Write-Progress -Activity "Disk Integrity Check" -Status "Scanning $($v.DriveLetter): $label" -PercentComplete $percent
                Write-Host "Checking $($v.DriveLetter): $label" -ForegroundColor Cyan

                Start-Process -FilePath "chkdsk.exe" -ArgumentList "$($v.DriveLetter): /scan" -Wait -NoNewWindow
                Log "Integrity check completed for $($v.DriveLetter):"
            }
        } else {
            $Global:SkippedCount++
            Log "No volumes detected."
            Write-Host "No volumes detected." -ForegroundColor Yellow
        }
    } catch {
        $Global:ErrorCount++
        Log "Disk Integrity error: $($_.Exception.Message)"
        Write-Host "Disk Integrity error: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Progress -Activity "Disk Integrity Check" -Status "Completed" -PercentComplete 100
    Log "Disk Integrity Check Completed."
    Write-Host "=== Disk Integrity Check Completed ===" -ForegroundColor Green
}





# =========================
# Security scans (Windows Defender)
# =========================
Function Ensure-Defender {
    Log "Checking Windows Defender status..."
    try {
        $service = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            Log "Windows Defender is running."
            Write-Host "Windows Defender is running." -ForegroundColor Green
        } elseif ($service) {
            Start-Service -Name WinDefend
            Log "Windows Defender service started."
            Write-Host "Windows Defender service started." -ForegroundColor Yellow
        } else {
            Log "Windows Defender service not found on this system."
            Write-Host "Windows Defender service not found." -ForegroundColor Red
        }
    } catch {
        $Global:ErrorCount++
        Log "Failed to check/start Windows Defender: $($_.Exception.Message)"
        Write-Host "Failed to check/start Windows Defender: $($_.Exception.Message)" -ForegroundColor Red
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
            Write-Host "Defender signature update error: $($_.Exception.Message)" -ForegroundColor Red
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
            Write-Host "Defender CLI scan error: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        $Global:SkippedCount++
        Log "Windows Defender CLI not found. Skipping Defender scan."
        Write-Host "Windows Defender CLI not found. Skipping Defender scan." -ForegroundColor Yellow
    }

    # Audit manual-start services
    Write-Host "Checking manual-start services currently running..." -ForegroundColor Yellow
    try {
        $ManualServices = Get-Service | Where-Object { $_.StartType -eq "Manual" -and $_.Status -eq "Running" }
        if ($ManualServices) {
            $ManualServices | Format-Table -AutoSize
            $Global:AuditCount++
            Log "Manual-start services audit completed."
        } else {
            $Global:SkippedCount++
            Log "No manual-start services currently running."
        }
    } catch {
        $Global:ErrorCount++
        Log "Service audit error: $($_.Exception.Message)"
        Write-Host "Service audit error: $($_.Exception.Message)" -ForegroundColor Red
    }

    Log "Security Scans Completed."
    Write-Host "=== Security Scans Completed ===" -ForegroundColor Green
}

# =========================
# Debloat Windows Apps + Telemetry Removal
# =========================
Function Debloat-Windows {
    if (-not $Global:EnableDebloat) {
        Log "Debloat disabled."
        return
    }

    Log "Debloating Windows apps and features..."
    Write-Host "=== Debloat Windows Apps + Telemetry Removal ===" -ForegroundColor Yellow

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
                        Write-Host "Error removing: $friendlyName" -ForegroundColor Red
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
        try {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            $Global:RepairCount++
            Log "Telemetry registry setting applied."
        } catch {
            $Global:ErrorCount++
            Log "Telemetry registry tweak error: $($_.Exception.Message)"
            Write-Host "Telemetry registry tweak error: $($_.Exception.Message)" -ForegroundColor Red
        }

        $TelemetryServices = @("DiagTrack","dmwappushservice","WerSvc","PcaSvc")
        foreach ($svc in $TelemetryServices) {
            try {
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
                $Global:RepairCount++
                Log "Disabled telemetry service: $svc"
            } catch {
                $Global:SkippedCount++
                Log "Skipped (protected or not present): $svc"
            }
        }
    } catch {
        $Global:ErrorCount++
        Log "Debloat error: $($_.Exception.Message)"
        Write-Host "Debloat error: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Progress -Activity "Debloating Windows" -Completed
    Log "Debloat Completed."
    Write-Host "=== Debloat Completed ===" -ForegroundColor Green
}

# =========================
# Check Windows Updates (Safe with Auto-Detect Release Health)
# =========================
Function Get-BlacklistedUpdates {
    $osCaption = (Get-CimInstance Win32_OperatingSystem).Caption
    $build     = (Get-ComputerInfo).WindowsVersion
    $url       = ""

    if ($osCaption -match "Windows 10") {
        switch -Regex ($build) {
            "22H2" { $url = "https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2" }
            "21H2" { $url = "https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-21h2" }
            default { $url = "https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2" }
        }
    } elseif ($osCaption -match "Windows 11") {
        switch -Regex ($build) {
            "25H2" { $url = "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-25h2" }
            "24H2" { $url = "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2" }
            default { $url = "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-25h2" }
        }
    } else {
        $url = "https://learn.microsoft.com/en-us/windows/release-health/"
    }

    try {
        Write-Progress -Activity "Fetching Release Health" -Status "Querying Microsoft..." -PercentComplete 50
        $html    = Invoke-WebRequest -Uri $url -UseBasicParsing
        $matches = [regex]::Matches($html.Content, "KB\d{7}")
        $kbList  = $matches.Value | Sort-Object -Unique
        Log "Fetched blacklist from Release Health ($url): $($kbList -join ', ')"
        Write-Progress -Activity "Fetching Release Health" -Status "Completed" -PercentComplete 100
        return $kbList
    } catch {
        Log "Failed to fetch Release Health dashboard: $($_.Exception.Message)"
        return @()
    }
}

Function Check-WindowsUpdates {
    Log "Checking for Windows Updates..."
    Write-Host "=== Checking Windows Updates ===" -ForegroundColor Yellow

    try {
        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue

        if (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue) {
            $updates = Get-WindowsUpdate -IgnoreUserInput -ErrorAction SilentlyContinue

            if ($updates -and $updates.Count -gt 0) {
                Write-Host "Pending updates found:" -ForegroundColor Cyan
                foreach ($u in $updates) {
                    $kbId = [regex]::Match($u.Title, "KB\d{7}").Value
                    Write-Host " - $($u.Title) [$kbId]" -ForegroundColor White
                    Log "Pending update: $($u.Title) [$kbId]"
                }

                # Fetch dynamic blacklist from Release Health
                $blacklist = Get-BlacklistedUpdates

                # Filter out blacklisted updates
                $safeUpdates = $updates | Where-Object {
                    $kbId = [regex]::Match($_.Title, "KB\d{7}").Value
                    $blacklist -notcontains $kbId
                }

                if ($safeUpdates.Count -lt $updates.Count) {
                    $bad = $updates | Where-Object {
                        $kbId = [regex]::Match($_.Title, "KB\d{7}").Value
                        $blacklist -contains $kbId
                    }
                    foreach ($b in $bad) {
                        $kbId = [regex]::Match($b.Title, "KB\d{7}").Value
                        Log "Blacklisted update detected: $($b.Title) [$kbId]"
                        Write-Host "⚠ Skipped blacklisted update: $($b.Title) [$kbId]" -ForegroundColor Yellow
                    }
                }

                if ($safeUpdates.Count -eq 0) {
                    $Global:SkippedCount++
                    Log "All pending updates are blacklisted/skipped."
                    Write-Host "All pending updates are blacklisted/skipped." -ForegroundColor Yellow
                } else {
                    $response = Read-Host "Proceed with installing $($safeUpdates.Count) safe updates? (Y/N)"
                    if ($response -match '^[Yy]$') {
                        Write-Progress -Activity "Installing Windows Updates" -Status "Starting..." -PercentComplete 10
                        try {
                            Install-WindowsUpdate -AcceptAll -IgnoreReboot -AutoReboot:$false
                            $Global:UpdateCount += $safeUpdates.Count
                            Log "Installed $($safeUpdates.Count) Windows updates."
                            Write-Host "Installed $($safeUpdates.Count) Windows updates." -ForegroundColor Green
                        } catch {
                            $Global:ErrorCount++
                            Log "Windows Update install error: $($_.Exception.Message)"
                            Write-Host "Windows Update install error: $($_.Exception.Message)" -ForegroundColor Red
                        }
                        Write-Progress -Activity "Installing Windows Updates" -Status "Completed" -PercentComplete 100
                    } else {
                        $Global:SkippedCount++
                        Log "User skipped Windows Update installation."
                        Write-Host "User skipped Windows Update installation." -ForegroundColor Yellow
                    }
                }
            } else {
                $Global:SkippedCount++
                Log "No Windows updates available."
                Write-Host "No Windows updates available." -ForegroundColor Cyan
            }
        } else {
            # Fallback to USOClient
            Log "PSWindowsUpdate not available, using USOClient..."
            try {
                Start-Process -FilePath "usoclient.exe" -ArgumentList "StartScan" -Wait
                $Global:RepairCount++
                Log "USOClient scan triggered."
                Write-Host "USOClient scan triggered." -ForegroundColor Green
            } catch {
                $Global:ErrorCount++
                Log "USOClient scan error: $($_.Exception.Message)"
                Write-Host "USOClient scan error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } catch {
        $Global:ErrorCount++
        Log "Windows Update error: $($_.Exception.Message)"
        Write-Host "Windows Update error: $($_.Exception.Message)" -ForegroundColor Red
    }

    Log "Windows Update check completed."
    Write-Host "=== Windows Update Check Completed ===" -ForegroundColor Green
}

# =========================
# Update System (Drivers + Winget Apps with Progress)
# =========================
Function Update-System {
    Log "Updating drivers and Winget apps..."
    Write-Host "=== Updating System ===" -ForegroundColor Yellow

    try {
        # Update drivers via pnputil
        Write-Host "Scanning for driver updates..." -ForegroundColor Yellow
        try {
            pnputil /scan-devices | Out-Null
            $Global:UpdateCount++
            Log "Driver scan completed."
            Write-Host "Driver scan completed." -ForegroundColor Green
        } catch {
            $Global:ErrorCount++
            Log "Driver update error: $($_.Exception.Message)"
            Write-Host "Driver update error: $($_.Exception.Message)" -ForegroundColor Red
        }

        # Update apps via Winget
        Write-Host "Checking for Winget application updates..." -ForegroundColor Yellow
        try {
            # Get list of upgradable apps
            $apps = winget upgrade | Select-String "^\S" | ForEach-Object {
                ($_ -split '\s{2,}')[0]
            }

            if ($apps -and $apps.Count -gt 0) {
                Write-Host "Pending app updates found:" -ForegroundColor Cyan
                foreach ($a in $apps) {
                    Write-Host " - $a" -ForegroundColor White
                    Log "Pending app update: $a"
                }

                $i = 0
                foreach ($a in $apps) {
                    $i++
                    $percent = [math]::Round(($i / $apps.Count) * 100)
                    Write-Progress -Activity "Updating Applications" -Status "Updating $a" -PercentComplete $percent

                    try {
                        winget upgrade --id $a --silent --accept-source-agreements --accept-package-agreements | Out-Null
                        $Global:UpdateCount++
                        Log "Updated application: $a"
                        Write-Host "Updated application: $a" -ForegroundColor Green
                    } catch {
                        $Global:ErrorCount++
                        Log "Winget update error for $a: $($_.Exception.Message)"
                        Write-Host "Winget update error for $a: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }

                Write-Progress -Activity "Updating Applications" -Status "Completed" -PercentComplete 100
                Log "Winget application updates completed."
                Write-Host "=== Winget Application Updates Completed ===" -ForegroundColor Green
            } else {
                $Global:SkippedCount++
                Log "No Winget application updates available."
                Write-Host "No Winget application updates available." -ForegroundColor Cyan
            }
        } catch {
            $Global:ErrorCount++
            Log "Winget update error: $($_.Exception.Message)"
            Write-Host "Winget update error: $($_.Exception.Message)" -ForegroundColor Red
        }
    } catch {
        $Global:ErrorCount++
        Log "System update error: $($_.Exception.Message)"
        Write-Host "System update error: $($_.Exception.Message)" -ForegroundColor Red
    }

    Log "System update completed."
    Write-Host "=== System Update Completed ===" -ForegroundColor Green
}


# =========================
# Network optimization
# =========================
Function Optimize-NetworkAuto {
    Log "Starting Auto Network Optimization..."
    Write-Host "=== Detecting Network Adapter Capability ===" -ForegroundColor Yellow

    $Results = @()

    try {
        $Adapters = Get-CimInstance Win32_NetworkAdapter -ErrorAction Stop | Where-Object { $_.NetEnabled -eq $true }

        if (-not $Adapters) {
            $Global:SkippedCount++
            Log "No active network adapters detected."
            Write-Host "No active network adapters detected." -ForegroundColor Cyan
        } else {
            foreach ($Adapter in $Adapters) {
                $NegotiatedMbps = if ($Adapter.Speed) { [math]::Round($Adapter.Speed / 1e6) } else { 0 }
                $Desc = $Adapter.Description

                $Result = [PSCustomObject]@{
                    Adapter     = $Adapter.Name
                    Description = $Desc
                    SpeedMbps   = $NegotiatedMbps
                }
                $Results += $Result

                $Global:AuditCount++
                Log "Adapter: $($Adapter.Name) [$Desc] Speed: $NegotiatedMbps Mbps"
            }

            Write-Host "`n=== Speedtest Visual ===" -ForegroundColor Magenta
            Add-Content -Path $LogFile -Value "`n=== Speedtest Visual ==="

            foreach ($Result in $Results) {
                $Bars = [math]::Round($Result.SpeedMbps / 100)
                if ($Bars -lt 1) { $Bars = 1 } # ensure at least one bar
                $BarString = ($Global:BarChar * $Bars)
                $Line = ("{0,-20} {1,6} Mbps | {2}" -f $Result.Adapter, $Result.SpeedMbps, $BarString)
                Write-Host $Line -ForegroundColor Cyan
                Add-Content -Path $LogFile -Value $Line
            }
        }

        Log "Network Optimization Completed."
        Write-Host "=== Network Optimization Completed ===" -ForegroundColor Green
    } catch {
        $Global:ErrorCount++
        Log "Network optimization error: $($_.Exception.Message)"
        Write-Host "Network optimization error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# =========================
# Performance Baseline
# =========================
Function Compare-PerformanceBaseline {
    Log "Starting Performance Baseline Comparison..."
    Write-Host "=== Performance Baseline ===" -ForegroundColor Yellow

    try {
        $Perf = Get-Counter '\Processor(_Total)\% Processor Time','\Memory\Available MBytes','\PhysicalDisk(_Total)\Avg. Disk Queue Length' -ErrorAction Stop

        $Results = @(
            [PSCustomObject]@{ Metric="CPU Usage";     Value="$([math]::Round($Perf.CounterSamples[0].CookedValue))%" },
            [PSCustomObject]@{ Metric="Available RAM"; Value="$([math]::Round($Perf.CounterSamples[1].CookedValue)) MB" },
            [PSCustomObject]@{ Metric="Disk Queue";    Value="$([math]::Round($Perf.CounterSamples[2].CookedValue,2))" }
        )

        # Output results to console and log
        $Results | Format-Table -AutoSize
        $Results | Out-String | Add-Content -Path $LogFile

        Write-Host "`n=== Performance Visual ===" -ForegroundColor Magenta
        Add-Content -Path $LogFile -Value "`n=== Performance Visual ==="

        foreach ($Result in $Results) {
            $Bars = switch ($Result.Metric) {
                "CPU Usage"     { [math]::Round(($Perf.CounterSamples[0].CookedValue) / 5) }
                "Available RAM" { [math]::Round(($Perf.CounterSamples[1].CookedValue) / 100) }
                "Disk Queue"    { [math]::Round(($Perf.CounterSamples[2].CookedValue) * 10) }
            }
            if ($Bars -lt 1) { $Bars = 1 } # ensure at least one bar
            $BarString = ($Global:BarChar * $Bars)
            $Line = ("{0,-15} {1,-15} | {2}" -f $Result.Metric, $Result.Value, $BarString)
            Write-Host $Line -ForegroundColor Cyan
            Add-Content -Path $LogFile -Value $Line
        }

        $Global:AuditCount++
        Log "Performance Baseline Completed."
        Write-Host "=== Performance Baseline Completed ===" -ForegroundColor Green
    } catch {
        $Global:ErrorCount++
        Log "Performance Baseline error: $($_.Exception.Message)"
        Write-Host "Performance Baseline error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# =========================
# Backup (robocopy, skips junctions, logs to file)
# =========================
Function Backup-UserData {
    Log "Starting Backup of User Data..."
    Write-Host "=== Backup User Data ===" -ForegroundColor Yellow

    $BackupSource      = "$env:USERPROFILE\Documents"
    $BackupDestination = "$PSScriptRoot\Backups"

    if (!(Test-Path -Path $BackupDestination)) {
        try {
            New-Item -ItemType Directory -Path $BackupDestination -Force | Out-Null
            Log "Created backup destination folder: $BackupDestination"
        } catch {
            $Global:ErrorCount++
            $Global:BackupStatus = "Failed"
            Log "Failed to create backup destination: $($_.Exception.Message)"
            Write-Host "Failed to create backup destination: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }

    $RoboArgs = "`"$BackupSource`" `"$BackupDestination`" /E /COPY:DAT /R:1 /W:1 /NFL /NDL /NP /XA:SH /XJ /LOG:$LogFile"

    try {
        $proc = Start-Process -FilePath "robocopy.exe" -ArgumentList $RoboArgs -NoNewWindow -PassThru -Wait
        if ($proc.ExitCode -le 3) {
            # Robocopy exit codes 0–3 are considered success/minor issues
            Write-Host "Backup Completed: $BackupSource to $BackupDestination" -ForegroundColor Green
            $Global:BackupStatus = "Success"
            $Global:RepairCount++
            Log "Backup completed successfully with exit code $($proc.ExitCode)."
        } else {
            $Global:BackupStatus = "Failed"
            $Global:ErrorCount++
            Log "Backup failed with exit code $($proc.ExitCode)."
            Write-Host "Backup failed with exit code $($proc.ExitCode)." -ForegroundColor Red
        }
    } catch {
        $Global:BackupStatus = "Failed"
        $Global:ErrorCount++
        Log "Backup error: $($_.Exception.Message)"
        Write-Host "Backup encountered an error: $($_.Exception.Message)" -ForegroundColor Red
    }

    Log "Backup process finished."
    Write-Host "=== Backup Process Finished ===" -ForegroundColor Cyan
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
        Write-Host "Event log analysis error: $($_.Exception.Message)" -ForegroundColor Red
    }

    if ($Global:ClearEventLogs) {
        Write-Host "Clearing Event Logs..." -ForegroundColor Yellow
        try {
            Get-EventLog -List | ForEach-Object {
                try {
                    Clear-EventLog -LogName $_.Log -ErrorAction SilentlyContinue
                    $Global:RepairCount++
                    Log "Cleared event log: $($_.Log)"
                } catch {
                    $Global:SkippedCount++
                    Log "Skipped clearing log $($_.Log): $($_.Exception.Message)"
                }
            }
            Log "Event Logs Cleared."
        } catch {
            $Global:ErrorCount++
            Log "Event log clear error: $($_.Exception.Message)"
            Write-Host "Event log clear error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Log "Event Log Analysis Completed."
    Write-Host "=== Event Log Analysis Completed ===" -ForegroundColor Green
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
    Write-Host "=== Audit Installed Software ===" -ForegroundColor Yellow

    $Cutoff = (Get-Date).AddMonths(-$Months)

    try {
        $Software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName } |
                    Sort-Object DisplayName

        foreach ($App in $Software) {
            $friendlyName = $App.DisplayName
            $lastUsed     = $App.InstallDate

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
                            Write-Host "Auto-removed unused software: $friendlyName" -ForegroundColor Green
                        } else {
                            $Global:SkippedCount++
                            Log "No uninstall string for: $friendlyName"
                            Write-Host "No uninstall string for: $friendlyName" -ForegroundColor Cyan
                        }
                    } catch {
                            $Global:ErrorCount++
                            Log "Error uninstalling ${friendlyName}: $($_.Exception.Message)"
                            Write-Host "Error uninstalling ${friendlyName}: $($_.Exception.Message)" -ForegroundColor Red
                    }


                } else {
                    $response = Read-Host "Remove $friendlyName (installed $parsedDate)? (Y/N)"
                    if ($response -match '^[Yy]$') {
                        try {
                            $UninstallString = $App.UninstallString
                            if ($UninstallString) {
                                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $UninstallString" -Wait
                                $Global:RemovedCount++
								Log "Error uninstalling ${friendlyName}: $($_.Exception.Message)"
								Write-Host "Error uninstalling ${friendlyName}: $($_.Exception.Message)" -ForegroundColor Red


                            } else {
                                $Global:SkippedCount++
                                Log "No uninstall string for: $friendlyName"
                                Write-Host "No uninstall string for: $friendlyName" -ForegroundColor Cyan
                            }
                        } catch {
                            $Global:ErrorCount++
                            Log "Error uninstalling ${friendlyName}: $($_.Exception.Message)"
                            Write-Host "Error uninstalling ${friendlyName}: $($_.Exception.Message)" -ForegroundColor Red
                        }
                    } else {
                        $Global:SkippedCount++
                        Log "User chose to keep: $friendlyName"
                        Write-Host "User chose to keep: $friendlyName" -ForegroundColor Yellow
                    }
                }
            } else {
                Log "Kept: $friendlyName (recently used or no usage data)"
                Write-Host "Kept: $friendlyName (recently used or no usage data)" -ForegroundColor Cyan
            }
        }
    } catch {
        $Global:ErrorCount++
        Log "Software audit error: $($_.Exception.Message)"
        Write-Host "Software audit error: $($_.Exception.Message)" -ForegroundColor Red
    }

    Log "Interactive software audit completed."
    Write-Host "=== Software Audit Completed ===" -ForegroundColor Green
}
# =========================
# Task Scheduling
# =========================
Function Schedule-Task {
    if (-not $Global:DoScheduleTask) {
        Log "Task scheduling disabled."
        return
    }

    Log "Configuring scheduled task for weekly optimization..."
    Write-Host "=== Scheduling Weekly Optimization Task ===" -ForegroundColor Yellow

    try {
        $Action    = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File `"$PSScriptRoot\CKMWinFix.ps1`""
        $Trigger   = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $Task      = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal

        Register-ScheduledTask -TaskName "CKMWinFix" -InputObject $Task -Force
        $Global:RepairCount++
        Log "Scheduled task 'CKMWinFix' created to run weekly."
        Write-Host "Scheduled task 'CKMWinFix' created to run weekly." -ForegroundColor Green
    } catch {
        $Global:ErrorCount++
        Log "Task scheduling error: $($_.Exception.Message)"
        Write-Host "Error creating scheduled task: $($_.Exception.Message)" -ForegroundColor Red
    }

    Log "Task Scheduling Completed."
    Write-Host "=== Task Scheduling Completed ===" -ForegroundColor Cyan
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
