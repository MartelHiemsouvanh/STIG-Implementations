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
    STIG-ID         : WN11-00-000126
    Documentation   : https://stigaview.com/products/win11/v2r11/WN11-00-000126/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-00-000126).ps1 
#>

#Requires -RunAsAdministrator

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount'

if (-not (Test-Path -Path $path)) {
    New-Item -Path $path -Force | Out-Null
}

New-ItemProperty -Path $path -Name 'DisableUserAuth' -PropertyType DWord -Value 0x00000001 -Force | Out-Null
