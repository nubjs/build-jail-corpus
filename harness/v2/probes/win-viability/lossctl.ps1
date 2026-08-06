# POSITIVE CONTROL FOR THE EVENT-LOSS COUNTER.
#
# ⛔ "eventsLost 0" IS THE LOAD-BEARING CLAIM OF THE WHOLE WINDOWS LANE, AND NOTHING HAS EVER SHOWN
# THAT NUMBER CAN BE ANYTHING ELSE. `windows.ps1` scrapes it out of `tracerpt -summary` with a regex
# against the line `Total Events Lost`; if that line is spelled differently, is absent, or the regex
# misses, `$lost` keeps its initialised value and the trace is declared complete. A zero that a
# broken reader produced is indistinguishable from a zero the kernel produced, and every downstream
# "no more than this" claim rests on telling them apart.
#
# So this deliberately STARVES the session -- the smallest buffers ETW accepts against a file-event
# storm -- and requires the counter to come back NONZERO. If it does not, the counter is not
# measuring loss and no trace on this platform can be called complete.
#
# The negative half of the control is the ordinary capture, which uses the real buffer configuration
# and must report zero on the SAME workload. A counter that reads nonzero everywhere is as useless as
# one that reads zero everywhere, so both directions are run.
#
#   usage: lossctl.ps1 -OutDir C:\obs\loss -Command C:\obs\storm.cmd -WorkDir C:\obs
#                      [-BufKB 1024 -MinBuf 64 -MaxBuf 320] [-Label real]
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$OutDir,
  [Parameter(Mandatory = $true)][string]$Command,
  [string]$WorkDir = (Get-Location).Path,
  [int]$BufKB = 1024,
  [int]$MinBuf = 64,
  [int]$MaxBuf = 320,
  [string]$Label = 'run',
  [int]$SettleMs = 800
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$etl = Join-Path $OutDir 'trace.etl'
$sum = Join-Path $OutDir 'summary.txt'
Remove-Item $etl, $sum -Force -ErrorAction SilentlyContinue

$Session = "nubloss_$PID`_$Label"
& logman stop $Session -ets 2>&1 | Out-Null
& logman create trace $Session -ets -o $etl -bs $BufKB -nb $MinBuf $MaxBuf -max 8192 | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Output "LOSSCTL[$Label] logman create FAILED $LASTEXITCODE"; exit 1 }
# The same three providers and the same keyword masks the real adapter uses, so the only variable
# between the two arms is the buffer configuration.
& logman update trace $Session -ets -p 'Microsoft-Windows-Kernel-File'    0x11F0 5 | Out-Null
& logman update trace $Session -ets -p 'Microsoft-Windows-Kernel-Network' 0x30   5 | Out-Null
& logman update trace $Session -ets -p 'Microsoft-Windows-Kernel-Process' 0x10   5 | Out-Null
Start-Sleep -Milliseconds $SettleMs

$p = Start-Process -FilePath $env:ComSpec -ArgumentList "/c $Command" -WorkingDirectory $WorkDir `
  -NoNewWindow -PassThru `
  -RedirectStandardOutput (Join-Path $OutDir 'run.out') `
  -RedirectStandardError  (Join-Path $OutDir 'run.err')
$null = $p.Handle
$p.WaitForExit()
$exitCode = $p.ExitCode
Start-Sleep -Milliseconds $SettleMs

# ⛔ READ THE SESSION'S OWN COUNTERS BEFORE STOPPING IT. `logman query -ets` reports the live
# session's `Buffers Lost` / `Events Lost`, which is the KERNEL's account. The tracerpt summary is a
# second, INDEPENDENT reading taken from the finished file. Two instruments disagreeing is itself the
# finding -- and the adapter today trusts only the second one.
$live = (& logman query $Session -ets 2>&1 | Out-String)
Set-Content -Path (Join-Path $OutDir 'logman-query.txt') -Value $live -Encoding Ascii

& logman stop $Session -ets | Out-Null
& tracerpt $etl -o (Join-Path $OutDir 'trace.xml') -of XML -summary $sum -lr -y | Out-Null
$tracerptExit = $LASTEXITCODE

$lost = -1; $processed = -1
if (Test-Path $sum) {
  foreach ($line in (Get-Content $sum)) {
    if ($line -match 'Total Events\s+Lost\s+(\d+)')      { $lost = [int]$Matches[1] }
    if ($line -match 'Total Events\s+Processed\s+(\d+)') { $processed = [int]$Matches[1] }
  }
}
$liveLost = -1; $liveBuffersLost = -1
foreach ($line in ($live -split "`r?`n")) {
  if ($line -match 'Events Lost:\s*(\d+)')  { $liveLost = [int]$Matches[1] }
  if ($line -match 'Buffers Lost:\s*(\d+)') { $liveBuffersLost = [int]$Matches[1] }
}

$etlBytes = if (Test-Path $etl) { (Get-Item $etl).Length } else { -1 }
$xmlBytes = if (Test-Path (Join-Path $OutDir 'trace.xml')) { (Get-Item (Join-Path $OutDir 'trace.xml')).Length } else { -1 }

$meta = [ordered]@{
  label = $Label; bufKB = $BufKB; minBuf = $MinBuf; maxBuf = $MaxBuf
  exitCode = $exitCode; tracerptExit = $tracerptExit
  eventsTotal = $processed; eventsLost = $lost
  liveEventsLost = $liveLost; liveBuffersLost = $liveBuffersLost
  etlBytes = $etlBytes; xmlBytes = $xmlBytes
}
$meta | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $OutDir 'loss.json') -Encoding Ascii
Write-Output ("LOSSCTL[$Label] bs=${BufKB}KB nb=$MinBuf/$MaxBuf  events=$processed  " +
  "tracerptLost=$lost  logmanEventsLost=$liveLost  logmanBuffersLost=$liveBuffersLost  etl=$etlBytes")
