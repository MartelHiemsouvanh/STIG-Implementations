<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Martel Hiemsouvanh
    LinkedIn        : https://www.linkedin.com/in/martel-hiemsouvanh-245ab8132/
    GitHub          : https://github.com/MartelHiemsouvanh
    Date Created    : 2026-11-01
    Last Modified   : 2026-11-01
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000586
    Documentation   : https://stigaview.com/products/win11/v2r11/WN11-AU-000586/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-AU-000586).ps1 
#>

# YOUR CODE GOES HERE


#Requires -RunAsAdministrator

$guid = '{0CCE921E-69AE-11D9-BED3-505054503030}'   # Audit Registry

# 1. Set the effective audit policy
auditpol /set /subcategory:$guid /success:enable | Out-Null

# 2. Make sure subcategory settings aren't overridden by legacy category policy
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'SCENoApplyLegacyAuditPolicy' -PropertyType DWord -Value 1 -Force | Out-Null

# 3. Record it in local Group Policy so gpedit.msc shows "Success"
$dir  = "$env:SystemRoot\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit"
$file = Join-Path $dir 'audit.csv'
$header = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
$row    = ',System,Audit Registry,{0cce921e-69ae-11d9-bed3-505054503030},Success,,1'

if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }

$lines = if (Test-Path $file) { @(Get-Content $file) } else { @($header) }
if ($lines.Count -eq 0) { $lines = @($header) }
$lines = @($lines | Where-Object { $_ -notmatch '0cce921e-69ae-11d9-bed3-505054503030' }) + $row
Set-Content -Path $file -Value $lines -Encoding ASCII

# 4. Verify
auditpol /get /subcategory:$guid
