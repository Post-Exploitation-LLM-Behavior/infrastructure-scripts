# Run as Administrator

# 1. Fetch release info with custom User-Agent
$apiUrl  = "https://api.github.com/repos/element-hq/element-desktop/releases/latest"
$release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "Mozilla/5.0" }
$asset   = $release.assets | Where-Object { $_.name -like "Element Setup*.exe" -or $_.name -like "*.exe" } | Select-Object -First 1

if (-not $asset) {
    Write-Error "Could not retrieve the download URL from GitHub API. Please check your internet connection or GitHub rate limits."
    return
}

$installer = "$env:TEMP\ElementSetup.exe"

Write-Host "Downloading Element from $($asset.browser_download_url)..."
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $installer

Write-Host "Installing Element..."
Start-Process -FilePath $installer -ArgumentList "/S" -Wait

# >>> EDIT THESE <<<
$homeserverBaseUrl = "https://your-homeserver.com"
$serverName        = "your-homeserver.com"

# Determine install directory and ensure path exists
$installDir = "C:\Program Files\Element"
if (-not (Test-Path $installDir)) { 
    $installDir = "$env:LOCALAPPDATA\Programs\Element" 
}

# Ensure directory exists before writing config
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