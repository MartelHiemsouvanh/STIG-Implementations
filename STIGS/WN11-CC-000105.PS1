<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Martel Hiemsouvanh
    LinkedIn        : https://www.linkedin.com/in/martel-hiemsouvanh-245ab8132/
    GitHub          : https://github.com/MartelHiemsouvanh
    Date Created    : 2026-11-07
    Last Modified   : 2026-11-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000105
    Documentation   : https://stigaview.com/products/win11/v2r11/WN11-CC-000105/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000105).ps1 
#>

# WN10-CC-000105 - Turn off Internet download for Web publishing and online ordering wizards
# Run as Administrator

$RegPath   = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$ValueName = "NoWebServices"
$Value     = 1

# Create the key if it doesn't exist
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set the policy value (REG_DWORD)
New-ItemProperty -Path $RegPath -Name $ValueName -Value $Value -PropertyType DWord -Force | Out-Null

# Verify
$result = Get-ItemProperty -Path $RegPath -Name $ValueName
if ($result.$ValueName -eq $Value) {
    Write-Host "Compliant: $ValueName = $($result.$ValueName)" -ForegroundColor Green
} else {
    Write-Host "Not compliant: $ValueName = $($result.$ValueName)" -ForegroundColor Red
}
