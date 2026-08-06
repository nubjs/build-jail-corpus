# KNOWN-ANSWER FIXTURE, grandchild half: the two write mechanisms Node's fs API cannot express.
#
# Both are real ways a package could put bytes on disk, and both bypass the ordinary WriteFile path
# the adapter's Write event watches:
#
#   memory-mapped write   the CPU stores into a mapped view and the MEMORY MANAGER flushes those
#                         pages later, on its own thread. There is no WriteFile call to observe at
#                         all, so if this shows up it is via a different mechanism entirely.
#   alternate data stream `file:stream` is a distinct NTFS stream on the same file. The kernel names
#                         it `<file>:<stream>:$DATA`, a spelling no path classifier expects.
#
# A second process level also exercises the grandchild attribution the adapter depends on.
param([Parameter(Mandatory = $true)][string]$Root)

$ErrorActionPreference = 'Continue'
$work = Join-Path $Root 'work'

# ── memory-mapped write ───────────────────────────────────────────────────────────────────────
#
# ⛔ THIS NEVER RAN, FOR THE WHOLE LIFE OF THIS FIXTURE, AND THE PROBE REPORTED IT AS A TRACER GAP.
# The five-argument overload takes a `String mapName`, and PowerShell marshals `$null` for a String
# parameter as the EMPTY STRING -- which the API rejects with "Map name cannot be an empty string."
# Every run threw there, the catch below printed to a console nobody read, and `mmap` came back
# ABSENT from the trace for the honest reason that no memory-mapped write was ever performed.
# MEASURED in run 31120238112 by copying this process's stdout out of the capture directory.
#
# The two-argument overload takes no map name at all and defaults to ReadWrite access, so the
# marshalling question cannot arise again. `[NullString]::Value` is the other fix and is what the
# variants probe uses where a FileStream overload is genuinely needed.
$mmapPath = Join-Path $work 'kaf-mmap.bin'
try {
  $mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($mmapPath, [System.IO.FileMode]::Open)
  $view = $mmf.CreateViewAccessor(0, 4096, [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
  for ($i = 0; $i -lt 4096; $i++) { $view.Write($i, [byte]0xAB) }
  $view.Flush(); $view.Dispose(); $mmf.Dispose()
  # THE POSITIVE CONTROL, and the reason the line above is trustworthy at all: read the byte back.
  # "MMAP ok" printed without this said only that no exception escaped.
  $back = [System.IO.File]::ReadAllBytes($mmapPath)[0]
  if ($back -eq 0xAB) { Write-Output "MMAP ok $mmapPath" }
  else { Write-Output ("MMAP failed: no exception, but the file still reads 0x{0:X2}" -f $back) }
} catch { Write-Output "MMAP failed: $_" }

# ── alternate data stream ─────────────────────────────────────────────────────────────────────
$adsHost = Join-Path $work 'kaf-ads-HOST.bin'
try {
  Set-Content -Path $adsHost -Stream 'kafstream' -Value 'known-answer-alternate-data-stream' -ErrorAction Stop
  Write-Output "ADS ok ${adsHost}:kafstream"
} catch { Write-Output "ADS failed: $_" }

# ── temp resolution, measured in the child's own context ──────────────────────────────────────
# ⛔ THE Q4 QUESTION IS "DOES THE API FOLLOW THE ENV", AND IT IS ANSWERED HERE RATHER THAN ASSUMED.
# GetTempPathW is documented to consult TMP, then TEMP, then USERPROFILE, then the Windows
# directory -- so an env redirect covers every caller that resolves temp through the API, and covers
# nothing that hardcodes a literal. Printing all four side by side is what separates the two.
Add-Type -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint GetTempPathW(uint n, System.Text.StringBuilder buf);
'@ -Name 'KafTmp' -Namespace 'Kaf' | Out-Null
$sb = New-Object System.Text.StringBuilder 1024
[void][Kaf.KafTmp]::GetTempPathW(1024, $sb)
Write-Output "TEMPPROBE GetTempPathW=$($sb.ToString())"
Write-Output "TEMPPROBE env:TMP=$($env:TMP)"
Write-Output "TEMPPROBE env:TEMP=$($env:TEMP)"
Write-Output "TEMPPROBE env:USERPROFILE=$($env:USERPROFILE)"
Write-Output "TEMPPROBE GetTempFileName=$([System.IO.Path]::GetTempPath())"
