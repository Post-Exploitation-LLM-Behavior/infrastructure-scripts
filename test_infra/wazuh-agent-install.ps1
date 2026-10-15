$WAZUH_MANAGER = "172.16.10.11"
$msi = "$env:USERPROFILE\Downloads\wazuh-agent-4.14.9-1.msi"
$log = "$env:USERPROFILE\Downloads\wazuh-install.log"

curl `
    -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.9-1.msi" `
    -OutFile $msi

$p = Start-Process msiexec.exe `
    -Verb RunAs `
    -Wait `
    -PassThru `
    -ArgumentList "/i `"$msi`" WAZUH_MANAGER=`"$WAZUH_MANAGER`" /L*V `"$log`""
$p.ExitCode
Test-Path "C:\Program Files (x86)\ossec-agent"

Start-Service wazuhsvc
Get-Service wazuhsvc

Select-String `
    -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" `
    -Pattern "<address>"
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30