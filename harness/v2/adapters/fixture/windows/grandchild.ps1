# Level 3 of the process tree. This is the shape nub's Node-level shim cannot see: a separate
# PowerShell process doing its own HTTP. It is also where the userprofile write happens, so an
# adapter that follows only the direct child reports neither.
$ErrorActionPreference = 'Stop'

# (a) WRITE under the user profile.
Set-Content -Path "$env:USERPROFILE\fx-userprofile-write.txt" -Value "home write" -Encoding Ascii

# (b) TCP CONNECT to a pinned peer. Raw socket, no DNS and no TLS, so the expected peer is exactly
# one address:port and the assertion has no moving parts.
$c = New-Object System.Net.Sockets.TcpClient
$c.Connect('1.1.1.1', 443)
$c.Close()

# (c) The dprint@0.19.2 shape: Invoke-WebRequest from PowerShell. Not part of the exact-set
# assertion (DNS and TLS pull in peers we do not control) but it is the case that matters.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
  Invoke-WebRequest -Uri 'https://registry.npmjs.org/dprint' -UseBasicParsing -TimeoutSec 25 -OutFile "$env:TEMP\fx-iwr.json" | Out-Null
} catch {
  Write-Output "GRANDCHILD-IWR-FAILED: $($_.Exception.Message)"
}
Write-Output "GRANDCHILD-OK"
