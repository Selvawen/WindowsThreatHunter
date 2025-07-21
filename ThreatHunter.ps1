<#
.THREATHUNTER.PS1
Author: Selvawen
Purpose: Live Windows Threat Hunting Script for Blue Team Operations

#>

param(
    [switch]$ScanProcesses,
    [switch]$ScanStartup,
    [switch]$ScanServices,
    [switch]$ExportCSV = $true
)

$ErrorActionPreference = "SilentlyContinue"
$report = @()
$logFile = "$PSScriptRoot\ThreatHunter.log"

function Log($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp $msg" | Out-File -Append -FilePath $logFile
}

function Get-FileHashSafe($path) {
    try {
        if (Test-Path $path) {
            return (Get-FileHash -Path $path -Algorithm SHA256).Hash
        }
    } catch {
        return "ErrorHashing"
    }
    return "N/A"
}

function Add-ReportEntry($type, $name, $path, $extra1 = "", $extra2 = "", $mitre = "") {
    $hash = Get-FileHashSafe $path
    $report += [PSCustomObject]@{
        Time       = Get-Date
        Type       = $type
        Name       = $name
        Path       = $path
        Hash       = $hash
        Extra1     = $extra1
        Extra2     = $extra2
        MITRE      = $mitre
    }
}

function Is-SuspiciousExecutable($path) {
    if (-not (Test-Path $path)) { return $false }
    $sig = Get-AuthenticodeSignature $path
    return $sig.Status -ne 'Valid'
}

function Get-SuspiciousProcesses {
    Log "Scanning running processes..."
    Write-Host "`n=== [PROCESS SCAN] ===" -ForegroundColor Cyan
    $userDirs = @("C:\Users\", "$env:TEMP", "$env:APPDATA")
    Get-Process | ForEach-Object {
        try {
            $exe = $_.Path
            if ($exe -and ($userDirs | Where-Object { $exe -like "$_*" }) -and (Is-SuspiciousExecutable $exe)) {
                $sig = Get-AuthenticodeSignature $exe
                Add-ReportEntry "Process" $_.Name $exe $_.Id $sig.Status "T1059"
            }
        } catch {}
    }
}

function Get-StartupEntries {
    Log "Scanning startup entries..."
    Write-Host "`n=== [STARTUP ENTRY SCAN] ===" -ForegroundColor Cyan
    $keys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($key in $keys) {
        Get-ItemProperty -Path $key | ForEach-Object {
            $_.PSObject.Properties | ForEach-Object {
                $name = $_.Name
                $path = $_.Value
                if ($path -and (Is-SuspiciousExecutable $path)) {
                    $sig = Get-AuthenticodeSignature $path
                    Add-ReportEntry "Startup" $name $path "" $sig.Status "T1547"
                }
            }
        }
    }
}

function Get-SuspiciousServices {
    Log "Scanning services..."
    Write-Host "`n=== [SERVICE SCAN] ===" -ForegroundColor Cyan
    Get-WmiObject Win32_Service | ForEach-Object {
        $path = $_.PathName -replace '"',''
        if ($path -and (Is-SuspiciousExecutable $path)) {
            $sig = Get-AuthenticodeSignature $path
            Add-ReportEntry "Service" $_.Name $path $_.StartMode $sig.Status "T1569"
        }
    }
}

# Run scans based on flags
if ($ScanProcesses) { Get-SuspiciousProcesses }
if ($ScanStartup)   { Get-StartupEntries }
if ($ScanServices)  { Get-SuspiciousServices }

# Export report
if ($ExportCSV -and $report.Count -gt 0) {
    $outFile = "$PSScriptRoot\ThreatHunter_Report_20250721_025437.csv"
    $report | Export-Csv -Path $outFile -NoTypeInformation
    Log "Report saved to $outFile"
    Write-Host "`n[+] Report saved to $outFile" -ForegroundColor Green
} elseif ($ExportCSV) {
    Write-Host "`n[-] No suspicious activity found." -ForegroundColor Yellow
    Log "No suspicious items to report."
}

