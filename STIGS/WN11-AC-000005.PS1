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
    STIG-ID         : WN11-AC-000005
    Documentation   : https://stigaview.com/products/win11/v2r11/WN11-AC-000005/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-AC-000005).ps1 
#>

<#
.SYNOPSIS
    Remediates WN10-AC-000005 / WN11-AC-000005
    Sets "Account lockout duration" to 15 minutes.
#>

# Must run as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

$LockoutDuration = 15   # minutes (STIG: 15 or greater, or 0)

# Apply the setting
net accounts /lockoutduration:$LockoutDuration | Out-Null

# Verify
$current = (net accounts | Select-String "Lockout duration").ToString().Split(":")[1].Trim()
Write-Output "Account lockout duration is now: $current minutes"

if ([int]$current -ge 15 -or [int]$current -eq 0) {
    Write-Output "COMPLIANT"
} else {
    Write-Output "NOT COMPLIANT"
}
