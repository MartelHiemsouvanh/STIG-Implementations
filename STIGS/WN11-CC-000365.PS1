<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Martel Hiemsouvanh
    LinkedIn        : https://www.linkedin.com/in/martel-hiemsouvanh-245ab8132/
    GitHub          : https://github.com/MartelHiemsouvanh
    Date Created    : 2026-11-06
    Last Modified   : 2026-11-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000365
    Documentation   : https://stigaview.com/products/win11/v2r11/WN11-CC-000365/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000365).ps1 
#>

<#
.SYNOPSIS
    Remediates WN10-CC-000365 / WN11-CC-000365
    Prevents Windows apps from being activated by voice while the system is locked.
#>

# Must run as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

$RegPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$ValueName = "LetAppsActivateWithVoiceAboveLock"
$ValueData = 2   # 0 = User in control, 1 = Force Allow, 2 = Force Deny

# Create the key if it doesn't exist
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Apply the setting
New-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -PropertyType DWord -Force | Out-Null

# Verify
$current = (Get-ItemProperty -Path $RegPath -Name $ValueName).$ValueName
Write-Output "$ValueName is now: $current"

if ($current -eq 2) {
    Write-Output "COMPLIANT"
} else {
    Write-Output "NOT COMPLIANT"
}
