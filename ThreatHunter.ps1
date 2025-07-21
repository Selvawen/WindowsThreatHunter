# ThreatHunter.ps1
# Author: Selvawen
# Purpose: Live Windows Threat Hunting Script (Refined)

$ErrorActionPreference = "SilentlyContinue"
$report = @()

function Add-ReportEntry($type, $name, $path, $extra1 = "", $extra2 = "") {
    $report += [PSCustomObject]@{
        Time       = Get-Date
        Type       = $type
        Name       = $name
        Path       = $path
        Extra1     = $extra1
        Extra2     = $extra2
    }
}

function Is-SuspiciousExecutable($path) {
    if (-not (Test-Path $path)) { return $false }
    $sig = Get-AuthenticodeSignature $path
    return $sig.Status -ne 'Valid'
}

function Get-SuspiciousProcesses {
    Write-Host "`n=== [PROCESS SCAN] ===" -ForegroundColor Cyan
    $userDirs = @("C:\Users\", "$env:TEMP", "$env:APPDATA")
    Get-Process | ForEach-Object {
        try {
            $exe = $_.Path
            if ($exe -and ($userDirs | Where-Object { $exe -like "$_*" }) -and (Is-SuspiciousExecutable $exe)) {
                $sig = Get-AuthenticodeSignature $exe
                Add-ReportEntry "Process" $_.Name $exe $_.Id $sig.Status
            }
        } catch {}
    }
}

function Get-StartupEntries {
    Write-Host "`n=== [STARTUP ENTRY SCAN] ===" -ForegroundColor Cyan
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Get-ItemProperty $path | ForEach-Object {
                $_.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                    $exe = $_.Value
                    if ($exe -and $exe -is [string] -and (Is-SuspiciousExecutable $exe)) {
                        $sig = Get-AuthenticodeSignature $exe
                        Add-ReportEntry "Startup" $_.Name $exe "UserFolder: $($exe -like 'C:\Users\*')" $sig.Status
                    }
                }
            }
        }
    }
}

function Get-ScheduledTasks {
    Write-Host "`n=== [SCHEDULED TASK SCAN] ===" -ForegroundColor Cyan
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | ForEach-Object {
        try {
            Add-ReportEntry "ScheduledTask" $_.TaskName $_.TaskPath $_.Principal.UserId $_.State
        } catch {}
    }
}

function Export-Report {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $folderPath = "C:\Users\YourUsername\Documents\ThreatHunter\Reports"

    if (!(Test-Path $folderPath)) {
        New-Item -Path $folderPath -ItemType Directory -Force | Out-Null
        Write-Host "[*] Created folder: $folderPath" -ForegroundColor DarkYellow
    }

    $outfile = "$folderPath\ThreatHunter-Report-$timestamp.csv"

    if ($report.Count -eq 0) {
        Write-Host "`n[!] No suspicious items found. No report will be saved." -ForegroundColor Yellow
    } else {
        $report | Export-Csv -Path $outfile -NoTypeInformation
        Write-Host "`n[*] Report saved to: $outfile" -ForegroundColor Green
    }
}

# === MAIN EXECUTION ===
Write-Host "`n===[ ThreatHunter by Selvawen - v2.0 ]===" -ForegroundColor Yellow

Get-SuspiciousProcesses
Get-StartupEntries
Get-ScheduledTasks

Write-Host "`n[*] Total suspicious items found: $($report.Count)" -ForegroundColor Cyan
Export-Report
Write-Host "`n[*] Script execution complete.`n" -ForegroundColor Gray
