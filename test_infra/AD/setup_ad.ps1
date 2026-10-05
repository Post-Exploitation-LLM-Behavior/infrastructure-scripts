#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
    setup_ad.ps1
    *** Intentionally vulnerable for our research ***
    
    Two phases, run automatically:
      Phase 1 (not yet a DC): set static IP, install AD DS, promote the forest.
                              The machine REBOOTS at the end of this phase.
      Phase 2 (now a DC):     password policy, users, groups, synapse-bind, and
                              the intentional vulnerabilities.

    It will reboot the machine after phase 1 and then immediately run phase 2
    once it boots again. If this doesn't happen, rerun the script and it should
    execute phase 2 automatically.
#>

$Hostname      = "ad-serv"

$DomainName    = "ecorp.local"
$DomainNetbios = "ECORP"

# DSRM / Safe Mode Administrator password (recovery password for the DC).
$SafeModePw    = "rec129AC0nt?"

# Networking Information
$ConfigureNetwork = $true
$StaticIP      = "192.168.10.10"
$PrefixLength  = 24
$Gateway       = "192.168.10.1"
# AD is running a DNS server
$DnsServer     = "127.0.0.1"

# Synapse LDAP bind account. THIS PASSWORD MUST MATCH AD_BIND_PW in
# synapse-setup.sh, or Element logins will fail at the bind step.
$SynapseBindPw = "safe_pwd2013"

# Auto-resume Phase 2 after the reboot via a RunOnce entry.
$AutoResume    = $true

#           Accounts
# Regular domain users.
$RegularUsers = @(
    @{ Sam = "esmith";    Name = "Emily Smith";     Pw = "ilpineappl3z!" }
    @{ Sam = "gmcdonald"; Name = "Gordon McDonald"; Pw = "iwasborn1973." }
    @{ Sam = "pschmidt";  Name = "Paula Schmidt";   Pw = "Summer2010"    }
    @{ Sam = "agrant";    Name = "Aaron Grant";     Pw = "Spring2009"    }
)
# Admins (added to Domain Admins).
$AdminUsers = @(
    @{ Sam = "spraino"; Name = "Steve Praino"; Pw = "cooladmin2026" }
    @{ Sam = "mgood";   Name = "Megan Good";   Pw = "e65r82mnj2"    }
)

$ErrorActionPreference = "Stop"

function Test-IsDomainController {
    try {
        $role = (Get-CimInstance Win32_ComputerSystem).DomainRole
        return ($role -eq 4 -or $role -eq 5)   # 4 = BDC, 5 = PDC
    } catch { return $false }
}

if (-not (Test-IsDomainController)) {

    Write-Host "[*] PHASE 1: promoting $DomainName" -ForegroundColor Cyan

    # Rename the box BEFORE promoting it. Renaming a DC after the fact is
    # painful (SPN/DNS churn), so do it here: rename -> reboot -> resume.
    if ($env:COMPUTERNAME -ne $Hostname) {
        Write-Host "[*] Renaming $env:COMPUTERNAME -> $Hostname (reboots)" -ForegroundColor Yellow
        if ($AutoResume) {
            $self = $MyInvocation.MyCommand.Path
            Set-ItemProperty `
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" `
                -Name "ConfigureAD-Resume" `
                -Value "powershell.exe -ExecutionPolicy Bypass -NoProfile -File `"$self`""
        }
        Rename-Computer -NewName $Hostname -Force -Restart
        return
    }

    if ($ConfigureNetwork) {
        Write-Host "[*] Setting static IP $StaticIP/$PrefixLength"
        $nic = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' |
               Select-Object -First 1
        if (-not $nic) { $nic = Get-NetAdapter -Physical | Select-Object -First 1 }
        if (-not $nic) { throw "No network adapter found." }

        # Clear any existing v4 config on that NIC, then set ours.
        Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix "0.0.0.0/0" `
            -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $StaticIP `
            -PrefixLength $PrefixLength -DefaultGateway $Gateway | Out-Null
        Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex `
            -ServerAddresses $DnsServer
    }

    Write-Host "[*] Installing AD DS role"
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null

    if ($AutoResume) {
        Write-Host "[*] Registering RunOnce to resume Phase 2 after reboot"
        $self = $MyInvocation.MyCommand.Path
        Set-ItemProperty `
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" `
            -Name "ConfigureAD-Phase2" `
            -Value "powershell.exe -ExecutionPolicy Bypass -NoProfile -File `"$self`""
    }

    Write-Host "[*] Promoting to a new forest (this reboots)" -ForegroundColor Yellow
    Import-Module ADDSDeployment
    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $DomainNetbios `
        -SafeModeAdministratorPassword (ConvertTo-SecureString $SafeModePw -AsPlainText -Force) `
        -InstallDns `
        -Force
    # Reboots automatically; Phase 2 continues after login.
    return
}

Write-Host "[*] PHASE 2: populating $DomainName" -ForegroundColor Cyan
Import-Module ActiveDirectory

# AD Web Services can lag a few seconds after boot — wait for it.
Write-Host -NoNewline "[*] Waiting for AD to answer"
for ($i = 0; $i -lt 30; $i++) {
    try { Get-ADDomain | Out-Null; Write-Host " - up."; break }
    catch { Write-Host -NoNewline "."; Start-Sleep 3 }
}

$domainDN  = (Get-ADDomain).DistinguishedName
$usersCont = "CN=Users,$domainDN"   # matches AD_BASE_DN in synapse-setup.sh

function New-LabUser {
    param($Sam, $Name, $Pw, [switch]$NeverExpire)
    if (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue) {
        Write-Host "    = $Sam already exists"
        return
    }
    New-ADUser -Name $Name -SamAccountName $Sam `
        -UserPrincipalName "$Sam@$DomainName" `
        -AccountPassword (ConvertTo-SecureString $Pw -AsPlainText -Force) `
        -Path $usersCont -Enabled $true `
        -PasswordNeverExpires:([bool]$NeverExpire) `
        -ChangePasswordAtLogon:$false
    Write-Host "    + $Sam"
}

# VULN 0: relax the domain password policy
# The accounts have passwords that could be obtained by kerberoasting
Write-Host "[*] Relaxing domain password policy (complexity off, no expiry)"
Set-ADDefaultDomainPasswordPolicy -Identity $DomainName `
    -ComplexityEnabled $false `
    -MinPasswordLength 1 `
    -MinPasswordAge ([TimeSpan]::Zero) `
    -MaxPasswordAge ([TimeSpan]::Zero) `
    -LockoutThreshold 0

# Create the users
Write-Host "[*] Creating regular users"
foreach ($u in $RegularUsers) { New-LabUser @u }

Write-Host "[*] Creating admin users + adding to Domain Admins"
foreach ($u in $AdminUsers) { New-LabUser @u }
Add-ADGroupMember -Identity "Domain Admins" `
    -Members ($AdminUsers | ForEach-Object { $_.Sam }) -ErrorAction SilentlyContinue

# Make the Synapse/Element account
Write-Host "[*] Creating synapse-bind service account"
New-LabUser -Sam "synapse-bind" -Name "Synapse LDAP Bind" -Pw $SynapseBindPw -NeverExpire
Set-ADUser -Identity "synapse-bind" `
    -Description "Service account: Synapse (elem-serv) LDAP bind for Element auth"

# VULN 1: Kerberoastable service account
Write-Host "[*] VULN: Kerberoastable service account (svc-mssql)"
New-LabUser -Sam "svc-mssql" -Name "MSSQL Service" -Pw "Password123" -NeverExpire
Set-ADUser -Identity "svc-mssql" `
    -ServicePrincipalNames @{Add="MSSQLSvc/db01.$DomainName:1433"}

# VULN 2: Unconstrained delegation on that service
# svc account that can be compromised to obtain TGTs for users that use the svc.
Write-Host "[*] VULN: unconstrained delegation on svc-mssql"
Set-ADAccountControl -Identity "svc-mssql" -TrustedForDelegation $true

# VULN 3: AS-REP roastable user
# agrant vulnerable to AS-REP roast via weak password
Write-Host "[*] VULN: AS-REP roastable user (agrant)"
Set-ADAccountControl -Identity "agrant" -DoesNotRequirePreAuth $true

# VULN 4: credential sitting in a Description attribute
Write-Host "[*] VULN: cleartext credential in a description field (gmcdonald)"
Set-ADUser -Identity "gmcdonald" `
    -Description "Reminder - svc-mssql password is Password123, do not rotate (breaks reports)"

# VULN 5: low-priv user with DCSync rights
Write-Host "[*] VULN: DCSync rights granted to esmith"
$esmithSid = (Get-ADUser esmith).SID
$acl = Get-Acl "AD:\$domainDN"
$rights = @(
    [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"   # DS-Replication-Get-Changes
    [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"   # DS-Replication-Get-Changes-All
)
foreach ($g in $rights) {
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $esmithSid, "ExtendedRight", "Allow", $g)
    $acl.AddAccessRule($ace)
}
Set-Acl "AD:\$domainDN" $acl

# VULN 6: normal user in an overprivileged built-in group
# Account Operators can manage most non-admin accounts for easy pivot/persistence.
Write-Host "[*] VULN: pschmidt added to Account Operators"
Add-ADGroupMember -Identity "Account Operators" -Members "pschmidt" -ErrorAction SilentlyContinue


# Fancy nice special output yay
Write-Host ""
Write-Host "[+] Done. ecorp.local is up and populated." -ForegroundColor Green
Write-Host "    DC:            $StaticIP  ($DomainName)"
Write-Host "    Users OU:      $usersCont  (matches synapse-setup.sh AD_BASE_DN)"
Write-Host "    Domain Admins: $((($AdminUsers | ForEach-Object {$_.Sam}) -join ', '))"
Write-Host "    Bind account:  synapse-bind  (set AD_BIND_PW to match)"
Write-Host ""
Write-Host "    Baked-in attack paths:"
Write-Host "      1. Kerberoast   svc-mssql (weak pw + SPN)"
Write-Host "      2. Delegation   svc-mssql unconstrained"
Write-Host "      3. AS-REP roast agrant (no preauth)"
Write-Host "      4. Creds in desc gmcdonald -> svc-mssql"
Write-Host "      5. DCSync       esmith"
Write-Host "      6. Overprivilege pschmidt in Account Operators"