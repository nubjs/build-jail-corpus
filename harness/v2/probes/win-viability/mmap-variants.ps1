# IS A MEMORY-MAPPED WRITE INVISIBLE TO ETW, OR DID WE JUST STOP LISTENING TOO EARLY?
#
# ⛔ THE KNOWN-ANSWER FIXTURE REPORTS `mmap` ABSENT AT EVERY KEYWORD MASK, and the raw trace holds
# exactly one event naming the file -- a `NameCreate` from the System process, which is the kernel's
# filename rundown and not an access. That is consistent with two VERY different worlds, and calling
# it a limit of ETW without separating them would be naming the wrong gap:
#
#   (1) the store never reached the disk inside the session. `MemoryMappedViewAccessor.Flush()` calls
#       FlushViewOfFile, which QUEUES the dirty pages; the mapped-page writer thread does the write
#       on its own schedule, and the fixture stops the trace 1.2 s after the child exits. A write
#       that lands after the stop is missing for a TIMING reason, and a longer settle recovers it.
#   (2) the memory manager's flush genuinely emits no Kernel-File event, because there is no
#       WriteFile to observe. That is a real blind spot and has to be named as one.
#
# ⛔ AND A THIRD THING HAS TO BE RULED OUT FIRST: that the mapping FAILED and nothing was ever
# written. The fixture's grandchild catches its own exception and still exits 0, so "MMAP failed"
# and "MMAP fine but unobserved" look identical downstream. Every variant here therefore READS ITS
# FILE BACK and prints the byte it finds. A variant whose content did not change is not evidence
# about the tracer at all, and says so.
#
# Each variant writes its OWN file so the arms cannot contaminate each other.
#
#   usage: powershell -File mmap-variants.ps1 -Root C:\obs\mmapfx
param([Parameter(Mandatory = $true)][string]$Root)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $Root | Out-Null

Add-Type -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool FlushFileBuffers(Microsoft.Win32.SafeHandles.SafeFileHandle h);
'@ -Name 'MmapFx' -Namespace 'NubMmap' | Out-Null

function New-Target([string]$name) {
  $p = Join-Path $Root $name
  # 0x11 is the SEED byte. A variant that still reads 0x11 at the end did not write, whatever else
  # the trace shows.
  [System.IO.File]::WriteAllBytes($p, (New-Object byte[] 65536))
  $bytes = [System.IO.File]::ReadAllBytes($p); $bytes[0] = 0x11
  [System.IO.File]::WriteAllBytes($p, $bytes)
  return $p
}

# ⛔ `$null` IS NOT NULL FOR A .NET `String` PARAMETER. PowerShell marshals it as the EMPTY STRING,
# and `CreateFromFile` rejects that with "Map name cannot be an empty string." That is precisely how
# this probe, and the known-answer fixture before it, spent their entire lives never performing a
# memory-mapped write while reporting the absence as a TRACER gap. `[NullString]::Value` is the
# marshalling-correct null; the two-argument path overload takes no map name at all and is used
# wherever a FileStream is not needed, so the question cannot arise there.
function Invoke-Mmap([string]$path, [int]$settleSec, [bool]$flushHandle) {
  if (-not $flushHandle) {
    # No FileStream needed: the overload with no map name, defaulting to ReadWrite access.
    $mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($path, [System.IO.FileMode]::Open)
    $view = $mmf.CreateViewAccessor(0, 4096, [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
    for ($i = 0; $i -lt 4096; $i++) { $view.Write($i, [byte]0xAB) }
    $view.Flush(); $view.Dispose(); $mmf.Dispose()
  } else {
    $fs = [System.IO.File]::Open($path, 'Open', 'ReadWrite', 'ReadWrite')
    try {
      $mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
        $fs, [NullString]::Value, 0, [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
        [System.IO.HandleInheritability]::None, $true)
      $view = $mmf.CreateViewAccessor(0, 4096, [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
      for ($i = 0; $i -lt 4096; $i++) { $view.Write($i, [byte]0xAB) }
      $view.Flush(); $view.Dispose(); $mmf.Dispose()
      # FlushFileBuffers on the underlying handle is the documented way to force the mapped pages
      # out synchronously. If THIS is what makes the write visible, the gap is a flush-timing one.
      [void][NubMmap.MmapFx]::FlushFileBuffers($fs.SafeFileHandle)
    } finally { $fs.Dispose() }
  }
  if ($settleSec -gt 0) { Start-Sleep -Seconds $settleSec }
}

$variants = @(
  @{ name = 'mmap-A-asfixture.bin';  settle = 0; flush = $false; what = 'Flush + Dispose only, exactly what the known-answer fixture does' },
  @{ name = 'mmap-B-sleep6.bin';     settle = 6; flush = $false; what = 'the same, then 6 s INSIDE the session so a lazy flush has time to land' },
  @{ name = 'mmap-C-flushbufs.bin';  settle = 2; flush = $true;  what = 'FlushFileBuffers on the backing handle, forcing the pages out synchronously' }
)

foreach ($v in $variants) {
  $p = New-Target $v.name
  try {
    Invoke-Mmap -path $p -settleSec $v.settle -flushHandle $v.flush
    $b = [System.IO.File]::ReadAllBytes($p)
    # THE POSITIVE CONTROL. Byte 0 is 0xAB only if the mapped store actually reached the file.
    Write-Output ("MMAPVAR {0} content=0x{1:X2} wrote={2}  ({3})" -f $v.name, $b[0], ($b[0] -eq 0xAB), $v.what)
  } catch {
    Write-Output ("MMAPVAR {0} EXCEPTION {1}" -f $v.name, $_)
  }
}

# An ordinary WriteFile to the same directory, as the arm that MUST come back. If this one is also
# missing from the trace the probe is broken and no verdict about mmap can be read off it.
$ctl = Join-Path $Root 'mmap-CONTROL-ordinary.bin'
[System.IO.File]::WriteAllBytes($ctl, [byte[]](1, 2, 3, 4))
Write-Output "MMAPVAR control ordinary write $ctl"
