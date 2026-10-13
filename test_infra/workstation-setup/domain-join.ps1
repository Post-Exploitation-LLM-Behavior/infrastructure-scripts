#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Joins a Windows 10 workstation to the ecorp.local Active Directory domain.

.DESCRIPTION
    Points the workstation's DNS at the domain controller, optionally renames the
    machine and places it in a target OU, then joins the domain and reboots.

    Run as Administrator. The AD DC must be up and serving DNS for
    ecorp.local before this runs.

.EXAMPLE
    # For workstation
    .\join_domain.ps1 -NewName ws-01

.EXAMPLE
    # For admin workstation
    .\join_domain.ps1 -NewName adm-01
#>

[CmdletBinding()]
param(
    [string] $Domain       = "ecorp.local",
    [string] $DnsServer    = "192.168.10.10",
    [string] $NewName      = "",
    [string] $OUPath       = "",
    [string] $JoinUser     = "ECORP\spraino",
    [string] $JoinPassword = "",
    [switch] $SkipDns,
    [switch] $NoReboot
)

$ErrorActionPreference = "Stop"

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok  ($m) { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Die ($m) { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

# Check if domain joined
$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.PartOfDomain -and $cs.Domain -ieq $Domain) {
    Ok "$($env:COMPUTERNAME) is already in $($cs.Domain). Nothing to do."
    exit 0
}
if ($cs.PartOfDomain) {
    Die "Already joined to a DIFFERENT domain ($($cs.Domain)). Leave it first; not touching it."
}

Write-Host "testing1"

# point DNS at the DC, confirm the SRV resolves, THEN run the join
$nic = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses 192.168.10.10
Clear-DnsClientCache
Resolve-DnsName -Type SRV -Name "_ldap._tcp.dc._msdcs.ecorp.local"   # expect ad-serv.ecorp.local

# Check to see if tamper protection is turned off, needs to be manually done in the interface otherwise changes won't persist
while ($true) {
    Write-Host "Checking Tamper protection"
    $tp = $null
    try {
        $tp = (Get-MpComputerStatus).IsTamperProtected
    } catch {
        Warn "Could not read Defender status: $($_.Exception.Message)"
    }

    if ($tp -eq $false) {
        Ok "Tamper Protection is OFF — continuing."
        break
    }

    Warn "Tamper Protection is ON (or unreadable)."
    Write-Host "    Disable it:"
    Write-Host "        Windows Security Virus and threat protection"
    Write-Host "        Manage settings"
    Write-Host "        Tamper Protection = Off"
    Write-Host "    Then press ENTER to re-check, or X then ENTER to cancel." -ForegroundColor Yellow

    $key = Read-Host "   >"
    if ($key -match '^[Xx]') {
        Die "Cancelled by user — Tamper Protection still enabled, no domain join performed."
    }
}

# Set the DNS server to the DC
if (-not $SkipDns) {
    $nic = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' |
           Sort-Object ifIndex | Select-Object -First 1
    if (-not $nic) { Die "No active network adapter found." }
    Info "Setting DNS on '$($nic.Name)' -> $DnsServer"
    Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $DnsServer
    Clear-DnsClientCache
}

# Verify that the domain is reachable
Info "Locating a domain controller for $Domain"
try {
    $srv    = Resolve-DnsName -Type SRV -Name "_ldap._tcp.dc._msdcs.$Domain" -ErrorAction Stop
    $dcName = ($srv | Where-Object { $_.NameTarget } | Select-Object -First 1).NameTarget
    if (-not $dcName) { throw "no SRV answer" }
    Ok "Found DC: $dcName"
} catch {
    Die "Can't locate a DC for $Domain via $DnsServer. Check the DC is up, serving DNS, and that -DnsServer is correct."
}

# Credentials
if ($JoinPassword) {
    Warn "Using a password passed on the command line (unattended mode)."
    $sec  = ConvertTo-SecureString $JoinPassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($JoinUser, $sec)
} else {
    Info "Enter the password for $JoinUser (an account allowed to join machines)"
    $cred = Get-Credential -UserName $JoinUser -Message "Domain-join account for $Domain"
}

# Domain Join
$join = @{
    DomainName  = $Domain
    Credential  = $cred
    Force       = $true
    ErrorAction = 'Stop'
}
if ($NewName) { $join.NewName = $NewName; Info "Renaming to '$NewName' during join" }
if ($OUPath)  { $join.OUPath  = $OUPath;  Info "Target OU: $OUPath" }

Info "Joining $Domain ..."
try {
    Add-Computer @join
    Ok "Joined $Domain."
} catch {
    Die "Join failed: $($_.Exception.Message)"
}

# Reboot to apply
if ($NoReboot) {
    Warn "Join staged -- reboot to complete it."
} else {
    Info "Rebooting in 5s to complete the join..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
}