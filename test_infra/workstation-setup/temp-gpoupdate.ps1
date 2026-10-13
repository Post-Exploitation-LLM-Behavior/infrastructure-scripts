Import-Module GroupPolicy
Import-Module ActiveDirectory

$dnsDomain = $env:USERDNSDOMAIN                      # ECORP.LOCAL
$domainDN  = (Get-ADDomain).DistinguishedName
$gpoName   = "ECORP-Disable-All-Local-Users"

# ── 1. Stage the script on NETLOGON (readable by every member at boot) ──
$netlogon = "\\$dnsDomain\NETLOGON"
$scriptBody = @'
# Runs as SYSTEM at boot. Disables (does NOT delete) every local account
# except the machine account, so only domain logon remains. Reapplies each boot.
Get-LocalUser |
    Where-Object { $_.Enabled -and $_.Name -notlike '*$' } |
    ForEach-Object { Disable-LocalUser -Name $_.Name -ErrorAction SilentlyContinue }
'@
Set-Content -Path "$netlogon\disable-local-users.ps1" -Value $scriptBody -Encoding UTF8 -Force

# ── 2. Create the GPO and stage psscripts.ini in its SYSVOL store ──
if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
    New-GPO -Name $gpoName | Out-Null
    Write-Host "[+] created GPO $gpoName"
} else {
    Write-Host "[=] GPO $gpoName already exists"
}

$gpoId  = (Get-GPO -Name $gpoName).Id.Guid
$polDir = "\\$dnsDomain\SYSVOL\$dnsDomain\Policies\{$gpoId}\Machine\Scripts"
New-Item -ItemType Directory -Path "$polDir\Startup" -Force | Out-Null

@"
[Startup]
0CmdLine=powershell.exe
0Parameters=-ExecutionPolicy Bypass -NoProfile -File \\$dnsDomain\NETLOGON\disable-local-users.ps1
"@ | Out-File "$polDir\psscripts.ini" -Encoding Unicode -Force

# ── 3. Register the Scripts client-side extension so members actually process it ──
# Without these GUIDs on gPCMachineExtensionNames, clients ignore psscripts.ini.
$gpoDN  = "CN={$gpoId},CN=Policies,CN=System,$domainDN"
$cse    = "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]"
Set-ADObject -Identity $gpoDN -Replace @{ gPCMachineExtensionNames = $cse }

# ── 4. Bump the GPO version so clients detect the change and re-process ──
$gpc     = Get-ADObject -Identity $gpoDN -Properties versionNumber
$newVer  = [int]$gpc.versionNumber + 2          # +2 bumps the computer-half of the version word
Set-ADObject -Identity $gpoDN -Replace @{ versionNumber = $newVer }
$gptIni  = "\\$dnsDomain\SYSVOL\$dnsDomain\Policies\{$gpoId}\gpt.ini"
"[General]`r`nVersion=$newVer" | Out-File $gptIni -Encoding ASCII -Force

# ── 5. Link at the domain root (hits every member; DC has no local users = no-op) ──
if (-not ((Get-GPInheritance -Target $domainDN).GpoLinks.DisplayName -contains $gpoName)) {
    New-GPLink -Name $gpoName -Target $domainDN -LinkEnabled Yes | Out-Null
    Write-Host "[+] linked $gpoName -> domain root"
}
Write-Host "[+] done"