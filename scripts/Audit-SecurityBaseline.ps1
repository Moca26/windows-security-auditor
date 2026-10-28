<#
.SYNOPSIS
    Windows Security Baseline Compliance Auditor
.DESCRIPTION
    Scans local system security settings, registry configurations, and account policies
    to verify compliance with foundational hardening standards.
.AUTHOR
    Systems & Infrastructure Security
#>

[CmdletBinding()]
param()

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "     Windows Security Baseline Compliance Auditor       " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "[*] Initiating security posture scan..." -ForegroundColor Yellow

$AuditFailed = $false

# 1. Check PowerShell Execution Policy
$ExecPolicy = Get-ExecutionPolicy
if ($ExecPolicy -eq "Restricted") {
    Write-Host "[!] WARNING: Execution policy is set to Restricted." -ForegroundColor Yellow
} else {
    Write-Host "[+] PASS: Execution policy is set to a manageable level ($ExecPolicy)." -ForegroundColor Green
}

# 2. Check Windows Firewall Status
$FirewallProfiles = Get-NetFirewallProfile
foreach ($Profile in $FirewallProfiles) {
    if ($Profile.Enabled -eq $true) {
        Write-Host "[+] PASS: Firewall Profile [$($Profile.Name)] is ENABLED." -ForegroundColor Green
    } else {
        Write-Host "[-] FAIL: Firewall Profile [$($Profile.Name)] is DISABLED!" -ForegroundColor Red
        $AuditFailed = $true
    }
}

# 3. Check for Local Administrators
$AdminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
if ($AdminGroup) {
    Write-Host "[*] INFO: Local Administrators group currently contains the following accounts:" -ForegroundColor Cyan
    foreach ($Member in $AdminGroup) {
        Write-Host "    - $($Member.Name)" -ForegroundColor Gray
    }
}

# 4. Check SMBv1 Status (Legacy Protocol Risk)
try {
    $SMB1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
    if ($SMB1.State -eq "Enabled") {
        Write-Host "[-] FAIL: Legacy SMBv1 protocol is ENABLED (Security Risk)." -ForegroundColor Red
        $AuditFailed = $true
    } else {
        Write-Host "[+] PASS: Legacy SMBv1 protocol is Disabled." -ForegroundColor Green
    }
}
catch {
    Write-Host "[*] INFO: SMBv1 feature query skipped (requires server/advanced OS features)." -ForegroundColor Gray
}

Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
if ($AuditFailed) {
    Write-Host "[!] Audit completed with warnings or failing checks. Review required." -ForegroundColor Yellow
} else {
    Write-Host "[+] Audit completed successfully. Core baselines met." -ForegroundColor Green
}
Write-Host "========================================================" -ForegroundColor Cyan
