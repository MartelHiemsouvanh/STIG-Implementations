<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Martel Hiemsouvanh
    LinkedIn        : https://www.linkedin.com/in/martel-hiemsouvanh-245ab8132/
    GitHub          : https://github.com/MartelHiemsouvanh
    Date Created    : 2026-11-03
    Last Modified   : 2026-11-03
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000280
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-SO-000280/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-SO-000280).ps1 
#>

#Requires -RunAsAdministrator
<#
    Enables the Windows LAPS policy "Name of administrator account to manage"
    (gpedit.msc > Computer Configuration > Administrative Templates > System > LAPS)
    and fills in the "Administrator account name" box.
    If the local account doesn't exist yet, it creates it and adds it to the
    local Administrators group first.

    Edits the Local Group Policy file directly - no internet / extra modules needed.
    gpedit.msc will show the policy as Enabled with the name filled in.
    Run in PowerShell ISE launched with "Run as administrator".
#>

# ===================== SETTING =====================
$AdminName = 'Administrator'      # value for "Administrator account name"
# ===================================================

$PolKey  = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
$PolName = 'AdministratorAccountName'
$RegPath = "HKLM:\$PolKey"
$GpoDir  = "$env:windir\System32\GroupPolicy"
$PolFile = "$GpoDir\Machine\Registry.pol"
$GptIni  = "$GpoDir\gpt.ini"

# ---------------------------------------------------------------------
# Registry.pol helpers
# ---------------------------------------------------------------------
function Get-PolString([byte[]]$b, [ref]$p) {
    $start = $p.Value
    while (-not ($b[$p.Value] -eq 0 -and $b[$p.Value + 1] -eq 0)) { $p.Value += 2 }
    $s = [Text.Encoding]::Unicode.GetString($b, $start, $p.Value - $start)
    $p.Value += 2
    return $s
}

function Read-PolFile([string]$path) {
    $list = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path $path)) { return ,$list }
    $b = [IO.File]::ReadAllBytes($path)
    if ($b.Length -le 8) { return ,$list }
    $p = [ref]8
    while ($p.Value -lt $b.Length) {
        $p.Value += 2                                   # [
        $key  = Get-PolString $b $p ; $p.Value += 2     # ;
        $name = Get-PolString $b $p ; $p.Value += 2     # ;
        $type = [BitConverter]::ToUInt32($b, $p.Value) ; $p.Value += 4 ; $p.Value += 2
        $size = [BitConverter]::ToUInt32($b, $p.Value) ; $p.Value += 4 ; $p.Value += 2
        $data = New-Object byte[] $size
        if ($size -gt 0) { [Array]::Copy($b, $p.Value, $data, 0, $size) }
        $p.Value += $size
        $p.Value += 2                                   # ]
        $list.Add([pscustomobject]@{ Key = $key; Name = $name; Type = $type; Data = $data })
    }
    return ,$list
}

function Write-PolFile([string]$path, $entries) {
    $u  = [Text.Encoding]::Unicode
    $ms = New-Object IO.MemoryStream
    $w  = New-Object IO.BinaryWriter($ms)
    $w.Write([byte[]](0x50, 0x52, 0x65, 0x67, 1, 0, 0, 0))     # "PReg" v1
    $open = $u.GetBytes('['); $semi = $u.GetBytes(';'); $close = $u.GetBytes(']'); $nul = [byte[]](0, 0)
    foreach ($e in $entries) {
        $w.Write($open)
        $w.Write($u.GetBytes($e.Key));  $w.Write($nul); $w.Write($semi)
        $w.Write($u.GetBytes($e.Name)); $w.Write($nul); $w.Write($semi)
        $w.Write([uint32]$e.Type);      $w.Write($semi)
        $w.Write([uint32]$e.Data.Length); $w.Write($semi)
        if ($e.Data.Length -gt 0) { $w.Write([byte[]]$e.Data) }
        $w.Write($close)
    }
    $w.Flush()
    $dir = Split-Path $path
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    [IO.File]::WriteAllBytes($path, $ms.ToArray())
    $w.Dispose()
}

# ---------------------------------------------------------------------
# 1. Check the account
# ---------------------------------------------------------------------
Write-Host "`n=== 1. Account ===" -ForegroundColor Cyan
$acct = Get-LocalUser -Name $AdminName -ErrorAction SilentlyContinue
if (-not $acct) {
    Write-Host "Local account '$AdminName' not found - creating it now." -ForegroundColor Yellow
    Write-Host "Password: at least 14 characters, with uppercase, lowercase, number and special character."

    function ConvertTo-Plain([securestring]$s) {
        $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
        try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
    }
    while ($true) {
        $pw1 = Read-Host "Enter password for '$AdminName'" -AsSecureString
        $pw2 = Read-Host "Confirm password" -AsSecureString
        $p1 = ConvertTo-Plain $pw1; $p2 = ConvertTo-Plain $pw2
        $problems = @()
        if ($p1 -cne $p2)                { $problems += 'passwords do not match' }
        if ($p1.Length -lt 14)           { $problems += 'shorter than 14 characters' }
        if ($p1 -cnotmatch '[A-Z]')      { $problems += 'no uppercase letter' }
        if ($p1 -cnotmatch '[a-z]')      { $problems += 'no lowercase letter' }
        if ($p1 -notmatch '[0-9]')       { $problems += 'no number' }
        if ($p1 -notmatch '[^A-Za-z0-9]'){ $problems += 'no special character' }
        $p1 = $null; $p2 = $null
        if ($problems.Count -eq 0) { break }
        Write-Host ("Try again: " + ($problems -join ', ')) -ForegroundColor Red
    }
    try {
        $acct = New-LocalUser -Name $AdminName -Password $pw1 -FullName 'Local Administrator (LAPS managed)' `
                    -Description 'Local admin - LAPS / alternate rotation' -ErrorAction Stop
        Write-Host "Created local user '$AdminName'." -ForegroundColor Green
    } catch {
        Write-Host "Could not create '$AdminName': $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    $pw1 = $null; $pw2 = $null
}

if (-not $acct.Enabled) { Enable-LocalUser -Name $acct.Name; Write-Host "Enabled '$($acct.Name)'." -ForegroundColor Green }

# Make sure it is in the local Administrators group
try {
    Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $acct.Name -ErrorAction Stop
    Write-Host "Added '$($acct.Name)' to the local Administrators group." -ForegroundColor Green
} catch {
    if ($_.Exception.Message -match 'already a member') {
        Write-Host "'$($acct.Name)' is already in the local Administrators group." -ForegroundColor Green
    } else {
        Write-Host "Could not add to Administrators group: $($_.Exception.Message)" -ForegroundColor Red
    }
}
$acct = Get-LocalUser -Name $acct.Name
Write-Host "Local account '$($acct.Name)' ready (Enabled: $($acct.Enabled))"

# ---------------------------------------------------------------------
# 2. Enable the policy in Local Group Policy (Registry.pol)
# ---------------------------------------------------------------------
Write-Host "`n=== 2. Enable 'Name of administrator account to manage' ===" -ForegroundColor Cyan

if (Test-Path $PolFile) {
    $backup = "$PolFile.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item $PolFile $backup -Force
    Write-Host "Backup of Local Group Policy file: $backup"
}

$entries = Read-PolFile $PolFile
# remove any existing value or "delete" marker for this setting
$keep = @($entries | Where-Object {
    -not ($_.Key -ieq $PolKey -and ($_.Name -ieq $PolName -or $_.Name -ieq "**del.$PolName"))
})
$keep += [pscustomobject]@{
    Key  = $PolKey
    Name = $PolName
    Type = 1                                                   # REG_SZ
    Data = [Text.Encoding]::Unicode.GetBytes($AdminName + [char]0)
}
Write-PolFile $PolFile $keep

# bump gpt.ini version and register the Registry extension so the policy is applied
$cseGuid = '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
$cse     = "[$cseGuid{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"
$lines   = if (Test-Path $GptIni) { @(Get-Content $GptIni) } else { @('[General]') }
$verLine = $lines | Where-Object { $_ -match '^\s*Version\s*=' } | Select-Object -First 1
$ver     = if ($verLine) { [int](($verLine -split '=')[1].Trim()) } else { 0 }
$lines   = @($lines | Where-Object { $_ -notmatch '^\s*Version\s*=' }) + "Version=$($ver + 1)"
if (-not ($lines | Where-Object { $_ -match '^\s*gPCMachineExtensionNames\s*=' })) {
    $lines += "gPCMachineExtensionNames=$cse"
} elseif (-not ($lines -match [regex]::Escape($cseGuid))) {
    $lines = $lines | ForEach-Object { if ($_ -match '^\s*gPCMachineExtensionNames\s*=') { $_ + $cse } else { $_ } }
}
Set-Content -Path $GptIni -Value $lines -Encoding ASCII

Write-Host "Policy set to Enabled, Administrator account name = '$AdminName'" -ForegroundColor Green

# ---------------------------------------------------------------------
# 3. Registry value (immediate effect)
# ---------------------------------------------------------------------
if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
Set-ItemProperty -Path $RegPath -Name $PolName -Value $AdminName -Type String

# ---------------------------------------------------------------------
# 4. Apply and verify
# ---------------------------------------------------------------------
Write-Host "`n=== 3. Apply and verify ===" -ForegroundColor Cyan
gpupdate /target:computer /force | Out-Null

$polCheck = (Read-PolFile $PolFile) | Where-Object { $_.Key -ieq $PolKey -and $_.Name -ieq $PolName }
$polValue = if ($polCheck) { [Text.Encoding]::Unicode.GetString($polCheck.Data).TrimEnd([char]0) } else { $null }
$regValue = (Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue).$PolName

[pscustomobject]@{
    'gpedit (Local Group Policy)' = if ($polValue) { "Enabled - $polValue" } else { 'Not Configured' }
    'Registry value'              = $regValue
} | Format-List

if ($polValue -eq $AdminName -and $regValue -eq $AdminName) {
    Write-Host "VERIFIED. Close and reopen gpedit.msc to see it as Enabled." -ForegroundColor Green
} elseif ($regValue -ne $AdminName) {
    Write-Host "The registry value changed after gpupdate - a domain GPO may be overriding it." -ForegroundColor Red
}
