# 2. Enable unauthenticated guest authentication over SMB
Write-Host "Configuring Guest SMB policies..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord

# 3. Disable anonymous listing restrictions in Windows LSA
Write-Host "Disabling anonymous LSA restrictions..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymoussam" -Value 0 -Type DWord

# 4. Enable the local Guest account
Write-Host "Enabling local Guest account..." -ForegroundColor Yellow
Enable-LocalUser -Name "Guest"

# 5. Create folder if it doesn't already exist
$FolderPath = "C:\SharedFolder"
if (-not (Test-Path -Path $FolderPath)) {
    Write-Host "Creating directory $FolderPath..." -ForegroundColor Yellow
    New-Item -Path $FolderPath -ItemType Directory | Out-Null
}

# 6. Create or update the SMB Share
$ShareName = "SharedFolder"
if (-not (Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue)) {
    Write-Host "Creating SMB Share '$ShareName'..." -ForegroundColor Yellow
    New-SmbShare -Name $ShareName -Path $FolderPath -FullAccess "Everyone" | Out-Null
} else {
    Write-Host "SMB Share '$ShareName' already exists. Updating permissions..." -ForegroundColor Yellow
}

# Grant SMB Share permissions to Everyone and ANONYMOUS LOGON
Grant-SmbShareAccess -Name $ShareName -AccountName "Everyone" -AccessRight Full -Force | Out-Null
Grant-SmbShareAccess -Name $ShareName -AccountName "ANONYMOUS LOGON" -AccessRight Full -Force | Out-Null

# 7. Apply local NTFS permissions
Write-Host "Setting NTFS permissions on $FolderPath..." -ForegroundColor Yellow
icacls $FolderPath /grant "Everyone:(OI)(CI)M" /Q
icacls $FolderPath /grant "ANONYMOUS LOGON:(OI)(CI)M" /Q