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
$mmapPath = Join-Path $work 'kaf-mmap.bin'
try {
  $mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
    $mmapPath, [System.IO.FileMode]::Open, $null, 0,
    [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
  $view = $mmf.CreateViewAccessor(0, 4096, [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
  for ($i = 0; $i -lt 4096; $i++) { $view.Write($i, [byte]0xAB) }
  $view.Flush(); $view.Dispose(); $mmf.Dispose()
  Write-Output "MMAP ok $mmapPath"
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
