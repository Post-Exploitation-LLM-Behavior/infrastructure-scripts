# Run as Administrator.
# Creates C:\Shared and exposes it as an SMB share.

Set-NetConnectionProfile -NetworkCategory Private
Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True

New-Item -Path "C:\Shared" -ItemType Directory -Force | Out-Null

if (-not (Get-SmbShare -Name "Shared" -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name "Shared" -Path "C:\Shared" -FullAccess "Everyone"
}

Write-Host "Share ready: \\$env:COMPUTERNAME\Shared"