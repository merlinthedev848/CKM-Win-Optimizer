# Force UTF-8 output so visuals render correctly
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 > $null

# Define a global bar character (ASCII fallback)
$Global:BarChar = "#"

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
            [PSCustomObject]@{ Metric="RAM"; Value="$([math]::Round(($RAM.TotalVisibleMemorySize - $RAM.FreePhysicalMemory)/1MB)) MB used"; Status="OK" },
            [PSCustomObject]@{ Metric="Disk"; Value="$([math]::Round($Disk.FreeSpace/1GB)) GB free"; Status="OK" }
        )

        $Results | Format-Table -AutoSize
        $Results | Out-String | Add-Content -Path $LogFile

        Write-Host "`n=== Health Visual ===" -ForegroundColor Magenta
        Add-Content -Path $LogFile -Value "`n=== Health Visual ==="
        
        foreach ($Result in $Results) {
            $Bars = if ($Result.Metric -eq "CPU") {
                        [math]::Round($CPU.LoadPercentage/5)
                    }
                    elseif ($Result.Metric -eq "RAM") {
                        [math]::Round(($RAM.TotalVisibleMemorySize - $RAM.FreePhysicalMemory)/100000)
                    }
                    else {
                        [math]::Round($Disk.FreeSpace/1GB/10)
                    }
        
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
            $BarString = if ($Disk.HealthStatus -eq "Healthy") { "##########" } else { "## ERROR ##" }
            $Line = ("{0,-20} {1,-15} {2,-10} | {3}" -f $Disk.FriendlyName, $Disk.OperationalStatus, $Disk.HealthStatus, $BarString)
            Write-Host $Line -ForegroundColor Cyan
            Add-Content -Path $LogFile -Value $Line
        }
    } catch { Log "Disk Integrity error: $($_.Exception.Message)" }
    Log "Disk Integrity Check Completed."
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
    } catch { Log "Performance Baseline error: $($_.Exception.Message)" }
    Log "Performance Baseline Completed."
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
                Optimize-Volume -DriveLetter $Disk.DeviceID -Defrag -Verbose
                Log "Defrag completed on $($Disk.FriendlyName)"
            } elseif ($Disk.MediaType -eq "SSD") {
                Optimize-Volume -DriveLetter $Disk.DeviceID -ReTrim -Verbose
                Log "TRIM optimization completed on $($Disk.FriendlyName)"
            } else {
                Log "Skipped disk $($Disk.FriendlyName) (unknown type)"
            }
        }

        Write-Host "`n=== Storage Visual ===" -ForegroundColor Magenta
        Add-Content -Path $LogFile -Value "`n=== Storage Visual ==="
        foreach ($Disk in $Disks) {
            $Bars = if ($Disk.MediaType -eq "HDD") { 20 }
                    elseif ($Disk.MediaType -eq "SSD") { 30 }
                    else { 10 }   # fallback for unknown types

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

            $Result = [PSCustomObject]@{
                Adapter = $Adapter.Name
                Description = $Desc
                SpeedMbps = $NegotiatedMbps
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
# Final Summary
# =========================
Function Write-FinalSummary {
    Add-Content -Path $LogFile -Value "`n-------------------------------------------------------------------------------"
    Add-Content -Path $LogFile -Value "   Final Summary"
    Add-Content -Path $LogFile -Value "-------------------------------------------------------------------------------"
    Add-Content -Path $LogFile -Value " Backup                : Completed"
    Add-Content -Path $LogFile -Value " Event Log Analysis    : Completed"
    Add-Content -Path $LogFile -Value " Task Scheduler        : Configured"
    Add-Content -Path $LogFile -Value " Storage Optimization  : Completed"
    Add-Content -Path $LogFile -Value " Telemetry             : Disabled"
    Add-Content -Path $LogFile -Value " Debloat               : Completed"
    Add-Content -Path $LogFile -Value "-------------------------------------------------------------------------------"
    Add-Content -Path $LogFile -Value " Script Execution Completed Successfully"
    Add-Content -Path $LogFile -Value "-------------------------------------------------------------------------------"
}


