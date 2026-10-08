# Run as Administrator
# Installs Element Desktop and points it at your homeserver.

$installer = "$env:TEMP\ElementSetup.exe"
$downloadUrl = "https://packages.element.io/desktop/update/win32/x64/Element%20Setup.exe"

Write-Host "Downloading Element Desktop..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $installer

# Verify download succeeded
if (-not (Test-Path $installer)) {
    Write-Error "Download failed. Please check your network connection."
    return
}

Write-Host "Installing Element Desktop..."
Start-Process -FilePath $installer -ArgumentList "/S" -Wait

# >>> EDIT THESE <<<
$homeserverBaseUrl = "https://your-homeserver.com"
$serverName        = "your-homeserver.com"

# Determine install directory and ensure path exists
$installDir = "C:\Program Files\Element"
if (-not (Test-Path $installDir)) { 
    $installDir = "$env:LOCALAPPDATA\Programs\Element" 
}

if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# Write configuration file
@{
    default_server_config = @{
        "m.homeserver" = @{
            base_url    = $homeserverBaseUrl
            server_name = $serverName
        }
    }
} | ConvertTo-Json -Depth 5 | Set-Content "$installDir\config.json"

Write-Host "Element installed and configured for $serverName"