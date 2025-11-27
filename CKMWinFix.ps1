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
$Global:EnableDebloat       = $true
$Global:EnableFullScan      = $false   # Defender full scan can be lengthy
$Global:EnableChkDsk        = $true    # May schedule next boot
$Global:ClearEventLogs      = $false   # Off by default; turn on if you want to purge
$Global:DoScheduleTask      = $true
$Global:EnableDriverUpdate  = $true    # Automatically update drivers via Windows Update
$Global:EnableSoftwareUpdate= $true    # Automatically update apps via Winget
$Global:FixPermissions = $true   # Set to $true to reset system permissions

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
    Write-Host "=== System Health Check ===" -ForegroundColor Yellow

    try {
        $CPU = Get-WmiObject Win32_Processor -Verbose
        $RAM = Get-WmiObject Win32_OperatingSystem -Verbose
        $Disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -Verbose

        $Results = @(
            [PSCustomObject]@{ Metric="CPU"; Value="$($CPU.LoadPercentage)%"; Status="OK" },
            [PSCustomObject]@{ Metric="RAM"; Value="$([math]::Round(($RAM.TotalVisibleMemorySize - $RAM.FreePhysicalMemory)/1MB)) MB used"; Status="OK" },
            [PSCustomObject]@{ Metric="Disk"; Value="$([math]::Round($Disk.FreeSpace/1GB)) GB free"; Status="OK" }
        )

        $Results | Format-Table -AutoSize
        $Results | Out-String | Add-Content -Path $LogFile

        # ASCII bar chart for RAM/disk
        Write-Host "`n=== Health Visual ===" -ForegroundColor Magenta
        foreach ($Result in $Results) {
            $Bars = if ($Result.Metric -eq "CPU") { [math]::Round($CPU.LoadPercentage/5) }
                    elseif ($Result.Metric -eq "RAM") { [math]::Round(($RAM.TotalVisibleMemorySize - $RAM.FreePhysicalMemory)/100000) }
                    else { [math]::Round($Disk.FreeSpace/1GB/10) }
            $BarString = ("█" * $Bars)
            Write-Host ("{0,-10} {1,-20} | {2}" -f $Result.Metric, $Result.Value, $BarString) -ForegroundColor Cyan
            Add-Content -Path $LogFile -Value ("{0,-10} {1,-20} | {2}" -f $Result.Metric, $Result.Value, $BarString)
        }
    } catch {
        Log "System Health error: $($_.Exception.Message)"
    }

    Log "System Health Check Completed."
}


# =========================
# Fix Permissions
# =========================

Function Fix-SystemPermissions {
    if (-not $Global:FixPermissions) { Log "Permission repair disabled."; return }

    Log "Resetting system permissions..."
    Write-Host "=== Resetting File and Registry Permissions ===" -ForegroundColor Yellow

    try {
        # Reset core folder ACLs
        icacls "C:\Windows" /reset /t /c /q | Out-Host
        icacls "C:\Program Files" /reset /t /c /q | Out-Host
        icacls "C:\Program Files (x86)" /reset /t /c /q | Out-Host

        # Reset registry & security policy
        secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose | Out-Host

        Log "System permissions reset to defaults."
    } catch {
        Log "Permission repair error: $_"
    }

    Log "Permission repair completed."
}

# =========================
# Disk Optimization (Defrag HDDs, TRIM SSDs)
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
    } catch {
        Log "Storage optimization error: $($_.Exception.Message)"
        Write-Host "Error during storage optimization: $($_.Exception.Message)" -ForegroundColor Red
    }

    Log "Storage Optimization Completed."
    Write-Host "=== Storage Optimization Completed ===" -ForegroundColor Green
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
    Log "Starting Disk Integrity Check..."
    Write-Host "=== Disk Integrity ===" -ForegroundColor Yellow

    try {
        $Disks = Get-PhysicalDisk -Verbose
        $Results = $Disks | Select FriendlyName, OperationalStatus, HealthStatus

        $Results | Format-Table -AutoSize
        $Results | Out-String | Add-Content -Path $LogFile

        Write-Host "`n=== Disk Visual ===" -ForegroundColor Magenta
        foreach ($Disk in $Results) {
            $BarString = if ($Disk.HealthStatus -eq "Healthy") { "██████████" } else { "██ ERROR ██" }
            Write-Host ("{0,-20} {1,-15} {2,-10} | {3}" -f $Disk.FriendlyName, $Disk.OperationalStatus, $Disk.HealthStatus, $BarString) -ForegroundColor Cyan
            Add-Content -Path $LogFile -Value ("{0,-20} {1,-15} {2,-10} | {3}" -f $Disk.FriendlyName, $Disk.OperationalStatus, $Disk.HealthStatus, $BarString)
        }
    } catch {
        Log "Disk Integrity error: $($_.Exception.Message)"
    }

    Log "Disk Integrity Check Completed."
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
# Driver's and Software Auto update
# =========================
Function Update-System {
    Log "Starting driver and software updates..."
    Write-Host "=== Updating Drivers and Software ===" -ForegroundColor Yellow

    try {
        # Update drivers via Windows Update
        Write-Host "Checking for driver updates..." -ForegroundColor Cyan
        Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot | Out-Host
        Log "Driver updates applied."

        # Update apps via Winget
        Write-Host "Updating installed applications..." -ForegroundColor Cyan
        winget upgrade --all --silent | Out-Host
        Log "Software updates applied."
    }
    catch {
        Log "Update error: $_"
    }

    Log "Driver and software updates completed."
}

# =========================
# Performance baseline (adds disk I/O and network throughput)
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
        foreach ($Result in $Results) {
            $Bars = if ($Result.Metric -eq "CPU Usage") { [math]::Round(($Perf.CounterSamples[0].CookedValue)/5) }
                    elseif ($Result.Metric -eq "Available RAM") { [math]::Round(($Perf.CounterSamples[1].CookedValue)/100) }
                    else { [math]::Round(($Perf.CounterSamples[2].CookedValue)*10) }
            $BarString = ("█" * $Bars)
            Write-Host ("{0,-15} {1,-15} | {2}" -f $Result.Metric, $Result.Value, $BarString) -ForegroundColor Cyan
            Add-Content -Path $LogFile -Value ("{0,-15} {1,-15} | {2}" -f $Result.Metric, $Result.Value, $BarString)
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
# Debloat Windows Apps + Telemetry Removal (Unified)
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
            "Microsoft.BioEnrollment",
            "Microsoft.CredDialogHost",
            "Microsoft.AccountsControl",
            "Microsoft.AsyncTextService",
            "Microsoft.Windows.FileExplorer",
            "Microsoft.VCLibs",
            "Microsoft.UI.Xaml",
            "Microsoft.NET.Native.Runtime",
            "Microsoft.NET.Native.Framework",
            "Microsoft.Copilot",
            "Windows.PrintDialog",
            "Microsoft.MicrosoftEdgeDevToolsClient",
            "Microsoft.Windows.Apprep.ChxApp",
            "Microsoft.Windows.AssignedAccessLockApp",
            "Microsoft.Windows.CallingShellApp",
            "Microsoft.Windows.ParentalControls",
            "Microsoft.XboxGameCallableUI",
            "NCSIUwpApp",
            "Microsoft.Windows.FilePicker",
            "Microsoft.Windows.AppResolverUX",
            "Microsoft.ECApp",
            "Microsoft.LockApp",
            "Microsoft.Win32WebViewHost",
            "Microsoft.Windows.CapturePicker",
            "Microsoft.Windows.ContentDeliveryManager",
            "Microsoft.Windows.NarratorQuickStart",
            "Microsoft.Windows.OOBENetworkCaptivePortal",
            "Microsoft.Windows.OOBENetworkConnectionFlow",
            "Microsoft.Windows.PeopleExperienceHost"
        )

        # Curated safe-to-remove apps
        $DebloatTargets = @(
            "Microsoft.3DBuilder",
            "Microsoft.MSPaint",                # Paint3D
            "Microsoft.Microsoft3DViewer",
            "Microsoft.SkypeApp",
            "Microsoft.XboxApp",
            "Microsoft.XboxGamingOverlay",
            "Microsoft.XboxIdentityProvider",
            "Microsoft.XboxSpeechToTextOverlay",
            "Microsoft.ZuneMusic",              # Groove Music
            "Microsoft.ZuneVideo",              # Movies & TV
            "Microsoft.GetHelp",
            "Microsoft.Getstarted",
            "Microsoft.MicrosoftOfficeHub",
            "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.People",
            "Microsoft.OneConnect",
            "Microsoft.MixedReality.Portal",
            "Microsoft.YourPhone"
        )

        # Remove curated apps only
        foreach ($Target in $DebloatTargets) {
            $App = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $Target }
            if ($App) {
                try {
                    Remove-AppxPackage -Package $App.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                    if ($?) { Log "Removed: $Target" } else { Log "Skipped: $Target" }
                } catch {
                    Log "Skipped (protected or system): $Target"
                }
            } else {
                Log "Not present: $Target"
            }
        }

        # Skip protected apps cleanly
        foreach ($App in $ProtectedApps) {
            Log "Skipped (protected): $App"
        }

        # OS-specific tweaks
        if ($ProductName -like "*Windows 10*") {
            Log "Disabling Cortana..."
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
        elseif ($ProductName -like "*Windows 11*") {
            Log "Targeted removals for Windows 11..."
            Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*WebExperience*" -or $_.Name -like "*MicrosoftTeams*" -or $_.Name -like "*YourPhone*" } | ForEach-Object {
                try {
                    Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                    if ($?) { Log "Removed: $($_.Name)" } else { Log "Skipped: $($_.Name)" }
                } catch { Log "Skipped (system): $($_.Name)" }
            }
            Log "Disabling Transparency..."
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }

        # Disable telemetry via registry
        Log "Disabling telemetry via registry..."
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -ErrorAction SilentlyContinue

        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue

        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue

        # Disable telemetry services
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

        # Disable telemetry scheduled tasks
        $TelemetryTasks = @(
            "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "\Microsoft\Windows\Autochk\Proxy",
            "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
            "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
        )
        foreach ($task in $TelemetryTasks) {
            try {
                schtasks /Change /TN $task /Disable
                Log "Disabled telemetry task: $task"
            } catch {
                Log "Skipped (protected or not present): $task"
            }
        }

    } catch {
        Log "Debloat error: $($_.Exception.Message)"
    }

    Write-Progress -Activity "Debloating Windows" -Completed
    Log "Debloat Completed."
}



# =========================
# Network optimization (capability + fallback + visual speedtest + log export)
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
            $Profile = "Conservative"

            Write-Host "Adapter: $($Adapter.Name)" -ForegroundColor Cyan
            Write-Host "Description: $Desc" -ForegroundColor Cyan
            Write-Host "Negotiated Speed: $NegotiatedMbps Mbps" -ForegroundColor Green
            Log "Adapter $($Adapter.Name) negotiated speed: $NegotiatedMbps Mbps"

            # Capability detection
            if ($Desc -match "10G" -or $Desc -match "10000") {
                $Profile = "10 Gbps"
                netsh int tcp set global rss=enabled
                netsh int tcp set global autotuninglevel=normal
                netsh int tcp set global chimney=disabled
            }
            elseif ($Desc -match "2.5G" -or $Desc -match "2500") {
                $Profile = "2.5 Gbps"
                netsh int tcp set global rss=enabled
                netsh int tcp set global autotuninglevel=normal
            }
            elseif ($Desc -match "1G" -or $Desc -match "1000") {
                $Profile = "1 Gbps"
                netsh int tcp set global rss=enabled
                netsh int tcp set global autotuninglevel=normal
            }
            elseif ($Desc -match "100M" -or $Desc -match "Fast Ethernet") {
                $Profile = "100 Mbps"
                netsh int tcp set global autotuninglevel=restricted
            }
            else {
                # Fallback: normalize negotiated speed
                if ($NegotiatedMbps -ge 950 -and $NegotiatedMbps -lt 1250) { $Profile = "1 Gbps" }
                elseif ($NegotiatedMbps -ge 2400 -and $NegotiatedMbps -lt 2600) { $Profile = "2.5 Gbps" }
                elseif ($NegotiatedMbps -ge 9500) { $Profile = "10 Gbps" }
                elseif ($NegotiatedMbps -ge 100) { $Profile = "100 Mbps" }
                else { $Profile = "Low-speed" }

                Write-Host "Fallback applied: $Profile profile" -ForegroundColor Yellow
            }

            Log "Profile applied: $Profile"
            $Results += [PSCustomObject]@{
                Adapter   = $Adapter.Name
                Desc      = $Desc
                SpeedMbps = $NegotiatedMbps
                Profile   = $Profile
            }
        }

        # Visual "speedtest" summary
        Write-Host "`n=== Speedtest Summary ===" -ForegroundColor Magenta
        $Results | Format-Table Adapter, SpeedMbps, Profile -AutoSize

        # ASCII bar chart
        Write-Host "`n=== Speedtest Visual ===" -ForegroundColor Magenta
        foreach ($Result in $Results) {
            $Bars = [math]::Round($Result.SpeedMbps / 100)  # scale: 1 bar per 100 Mbps
            $BarString = ("█" * $Bars)
            Write-Host ("{0,-20} {1,6} Mbps | {2}" -f $Result.Adapter, $Result.SpeedMbps, $BarString) -ForegroundColor Cyan
        }

        # Log export of summary + chart
        Add-Content -Path $LogFile -Value "`n=== Speedtest Summary ==="
        $Results | Out-String | Add-Content -Path $LogFile
        Add-Content -Path $LogFile -Value "`n=== Speedtest Visual ==="
        foreach ($Result in $Results) {
            $Bars = [math]::Round($Result.SpeedMbps / 100)
            $BarString = ("█" * $Bars)
            Add-Content -Path $LogFile -Value ("{0,-20} {1,6} Mbps | {2}" -f $Result.Adapter, $Result.SpeedMbps, $BarString)
        }

    } catch {
        Log "Network auto-optimization error: $($_.Exception.Message)"
        Write-Host "Network auto-optimization error: $($_.Exception.Message)" -ForegroundColor Red
    }

    Log "Auto Network Optimization Completed."
    Write-Host "=== Network Optimization Completed ===" -ForegroundColor Green
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
    Optimize-NetworkAuto
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
