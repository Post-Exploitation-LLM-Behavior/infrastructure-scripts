# powershell -ExecutionPolicy Bypass -File user_setup.ps1
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

& "$here\element_config.ps1"
& "$here\fileshare.ps1"