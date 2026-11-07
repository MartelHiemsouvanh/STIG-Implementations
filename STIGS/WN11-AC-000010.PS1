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
    STIG-ID         : WN11-AC-000010
    Documentation   : https://stigaview.com/products/win11/v2r11/WN11-AC-000010/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-AC-000010).ps1 
#>

<#
.SYNOPSIS
    Remediates WN10-AC-000010 / WN11-AC-000010
    Sets "Account lockout threshold" to 3 invalid logon attempts.
#>

# Must run as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

$LockoutThreshold = 3   # STIG: 1-3 (0 is NOT allowed)

# Apply the setting
net accounts /lockoutthreshold:$LockoutThreshold | Out-Null

# Verify
$current = (net accounts | Select-String "Lockout threshold").ToString().Split(":")[1].Trim()
Write-Output "Account lockout threshold is now: $current"

if ($current -ne "Never" -and [int]$current -ge 1 -and [int]$current -le 3) {
    Write-Output "COMPLIANT"
} else {
    Write-Output "NOT COMPLIANT"
}
