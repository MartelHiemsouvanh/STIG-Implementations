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
    STIG-ID         : WN11-CC-000280
    Documentation   : https://stigaview.com/products/win11/v2r11/WN11-CC-000280/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000280).ps1 
#>

#Requires -RunAsAdministrator

$base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

# Key path -> values to set (Name = @(Type, Value))
$settings = [ordered]@{
    "$base" = @{
        'KeepAliveEnable'   = @('DWord', 1)
        'KeepAliveInterval' = @('DWord', 1)
        'fPromptForPassword' = @('DWord', 1)
    }
    "$base\Client" = @{
        'fEnableUsbBlockDeviceBySetupClass' = @('DWord', 1)
        'fEnableUsbNoAckIsochWriteToDevice' = @('DWord', 0x50)   # 80 decimal
        'fEnableUsbSelectDeviceByInterface' = @('DWord', 1)
    }
    "$base\Client\UsbBlockDeviceBySetupClasses" = @{
        '1000' = @('String', '{3376f4ce-ff8d-40a2-a80f-bb4359d1415c}')
    }
    "$base\Client\UsbSelectDeviceByInterfaces" = @{
        '1000' = @('String', '{6bdd1fc6-810f-11d0-bec7-08002be2092f}')
    }
}

foreach ($path in $settings.Keys) {
    if (-not (Test-Path -Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }

    foreach ($name in $settings[$path].Keys) {
        $type, $value = $settings[$path][$name]
        New-ItemProperty -Path $path -Name $name -PropertyType $type -Value $value -Force | Out-Null
    }
}

# Verify
foreach ($path in $settings.Keys) {
    Write-Host "`n$path" -ForegroundColor Cyan
    Get-ItemProperty -Path $path |
        Select-Object -Property ([string[]]$settings[$path].Keys) |
        Format-List
}
