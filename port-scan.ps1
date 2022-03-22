Function port-scan-tcp {
  param($hosts,$ports)
  if (!$ports) {
    Write-Host "usage: port-scan-tcp <host|hosts> <port|ports>"
    Write-Host " e.g.: port-scan-tcp 192.168.1.2 445`n"
    return
  }
  foreach($p in [array]$ports) {
   foreach($h in [array]$hosts) {
    $msg = "TCP Port $p on host $h is "
    $t = new-Object system.Net.Sockets.TcpClient
    $c = $t.ConnectAsync($h,$p)
    for($i=0; $i -lt 10; $i++) {
      if ($c.isCompleted) { break; }
      sleep -milliseconds 100
    }
    $t.Close();
    $r = "Filtered"
    if ($c.isFaulted -and $c.Exception -match "actively refused") {
      $r = "Closed"
    } elseif ($c.Status -eq "RanToCompletion") {
      $r = "Open"
    }
    $msg += $r
    Write-Host "$msg"
   }
  }
}

# .NET 4.5

# Examples:
#
# port-scan-tcp 10.10.0.1 137
# port-scan-tcp 10.10.0.1 (135,137,445)
# port-scan-tcp (gc .\ips.txt) 137
# port-scan-tcp (gc .\ips.txt) (135,137,445)
# 0..255 | foreach { port-scan-tcp 10.10.0.$_ 137 }
# 0..255 | foreach { port-scan-tcp 10.10.0.$_ (135,137,445) }
