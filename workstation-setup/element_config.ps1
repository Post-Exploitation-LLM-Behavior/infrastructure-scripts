# Run as Administrator.
# Installs Element Desktop and points it at your homeserver.

$apiUrl  = "https://api.github.com/repos/element-hq/element-desktop/releases/latest"
$release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
$asset   = $release.assets | Where-Object { $_.name -match "Setup.*\.exe$" } | Select-Object -First 1
$installer = "$env:TEMP\ElementSetup.exe"

Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $installer
Start-Process -FilePath $installer -ArgumentList "/S" -Wait

# >>> EDIT THESE <<<
$homeserverBaseUrl = ""
$serverName        = ""

$installDir = "C:\Program Files\Element"
if (-not (Test-Path $installDir)) { $installDir = "$env:LOCALAPPDATA\Programs\Element" }

@{
    default_server_config = @{
        "m.homeserver" = @{
            base_url    = $homeserverBaseUrl
            server_name = $serverName
        }
    }
} | ConvertTo-Json -Depth 5 | Set-Content "$installDir\config.json"

Write-Host "Element installed and configured for $serverName"