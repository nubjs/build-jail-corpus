# Windows god-mode observation adapter, capture half.
#
# Runs a command under a system-wide ETW session and leaves behind everything windows.mjs needs to
# emit the normalized event stream. This half deliberately does no interpretation at all: it
# captures, it converts, and it records the ground truth the parser cannot recover on its own
# (which PID was the root, what the device-to-drive map was, whether the kernel dropped events).
#
# THE SPLIT THIS BELONGS TO. Generation runs on our boxes and may use ETW freely; the shipped build
# jail runs unprivileged on a stranger's machine. Nothing here is available to, or required by, the
# jail. This script needs an elevated token -- ETW kernel providers are administrator-only.
#
#   usage: powershell -NoProfile -ExecutionPolicy Bypass -File windows.ps1 `
#            -OutDir C:\obs\run1 -Command "npm install --ignore-scripts=false" -WorkDir C:\obs\proj
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$OutDir,
  [Parameter(Mandatory = $true)][string]$Command,
  [string]$WorkDir = (Get-Location).Path,
  [string]$Session = 'nubobs',
  [int]$MaxMB = 8192,
  [int]$SettleMs = 1200
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------------------------
# ELEVATION PERTURBS THE MEASUREMENT, so the perturbation is removed rather than caveated.
#
# libuv's fs__open sets FILE_FLAG_BACKUP_SEMANTICS on EVERY file open (deps/uv/src/win/fs.c:610).
# Combined with the SeBackupPrivilege/SeRestorePrivilege that an elevated token carries, that
# bypasses the DACL outright: measured on nub-win3, a Node write into a directory carrying an
# explicit Deny ACE for the running user SUCCEEDED under the elevated harness and was refused
# (EPERM) with the two privileges removed, with nothing else changed.
#
# That is not a cosmetic difference. A package that probes a location, is refused, and falls back
# elsewhere would be observed taking the probe and never the fallback -- a grant that is both wider
# than needed and missing the need that is real. Removing the privileges is irreversible for this
# token, which is fine: the token is short-lived, an unprivileged user never had them, and ETW is
# gated on administrator group membership rather than on these (verified: logman create/stop still
# exit 0 afterwards).
# ---------------------------------------------------------------------------------------------
$tokSrc = @'
[StructLayout(LayoutKind.Sequential)] public struct LUID { public uint LowPart; public int HighPart; }
[StructLayout(LayoutKind.Sequential)] public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
[StructLayout(LayoutKind.Sequential)] public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }
[DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
[DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool LookupPrivilegeValue(string sys, string name, out LUID luid);
[DllImport("advapi32.dll", SetLastError=true)] public static extern bool AdjustTokenPrivileges(IntPtr tok, bool disableAll, ref TOKEN_PRIVILEGES newState, uint len, IntPtr prev, IntPtr retLen);
public static string Drop(string name) {
  IntPtr tok;
  if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out tok)) return "OpenProcessToken:" + Marshal.GetLastWin32Error();
  LUID luid;
  if (!LookupPrivilegeValue(null, name, out luid)) return "LookupPrivilegeValue:" + Marshal.GetLastWin32Error();
  TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
  tp.PrivilegeCount = 1; tp.Privilege.Luid = luid;
  tp.Privilege.Attributes = 0x00000004;   // SE_PRIVILEGE_REMOVED
  if (!AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return "AdjustTokenPrivileges:" + Marshal.GetLastWin32Error();
  int e = Marshal.GetLastWin32Error();
  return (e == 1300) ? "already-absent" : "removed";   // ERROR_NOT_ALL_ASSIGNED
}
'@
# Add-Type -MemberDefinition already emits `using System.Runtime.InteropServices;`; passing
# -UsingNamespace duplicates it and the duplicate is a warning promoted to a compile error.
# Declaring structs makes -PassThru return an ARRAY of types, so the class has to be picked out.
$tokTypes = Add-Type -MemberDefinition $tokSrc -Name 'NubTok' -Namespace 'NubObs' -PassThru
$Tok = @($tokTypes) | Where-Object { $_.Name -eq 'NubTok' }
$dropped = [ordered]@{}
foreach ($priv in 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege') {
  $dropped[$priv] = $Tok::Drop($priv)
}

# ---------------------------------------------------------------------------------------------
# Preconditions. Both of these have already invalidated a run on these boxes, so they are asserted
# rather than assumed, and the answers are recorded in meta.json for whoever reads the results.
# ---------------------------------------------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$id).IsInRole(544)
if (-not $elevated) { throw "windows.ps1 needs an elevated token; ETW kernel providers are admin-only" }
# RUN AS THE INTERACTIVE USER, NEVER AS SYSTEM. A SYSTEM-context reproduction is the wrong
# security context and silently changes which paths are writable.
if ($id.User.Value -eq 'S-1-5-18') { throw "refusing to trace as SYSTEM ($($id.Name)); run as the interactive user" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$etl = Join-Path $OutDir 'trace.etl'
$xml = Join-Path $OutDir 'trace.xml'
$sum = Join-Path $OutDir 'summary.txt'
Remove-Item $etl, $xml, $sum -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------------------------
# Device map. Kernel-File reports NT paths (\Device\HarddiskVolume3\Users\...), never DOS paths.
# The mapping is queried from the kernel, not guessed from the path text, and is passed to the
# parser -- normalization rule 2 says roots are measured, never inferred.
# ---------------------------------------------------------------------------------------------
$sig = @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, uint ucchMax);
'@
$k32 = Add-Type -MemberDefinition $sig -Name 'NubDosDev' -Namespace 'NubObs' -PassThru
$devmap = @{}
foreach ($ch in [char[]]([char]'A'..[char]'Z')) {
  $sb = New-Object System.Text.StringBuilder 2048
  if ($k32::QueryDosDevice("$ch`:", $sb, 2048) -gt 0) {
    $target = $sb.ToString()
    if ($target) { $devmap[$target] = "$ch`:" }
  }
}

# ---------------------------------------------------------------------------------------------
# The session.
#
#   Kernel-File     0x1FF0  FILENAME | FILEIO | OP_END | CREATE | READ | WRITE | DELETE_PATH |
#                           RENAME_SETLINK_PATH | CREATE_NEW_FILE
#   Kernel-Network  0x30    IPV4 | IPV6
#   Kernel-Process  0x10    WINEVENT_KEYWORD_PROCESS -- Start carries ParentProcessID, which is
#                           the ONLY way to follow grandchildren
#
# ⛔ THE MASK WAS 0x11F0 AND ITS COMMENT NAMED NINE KEYWORDS IT DID NOT CARRY. Decoded against the
# provider's own `wevtutil gp Microsoft-Windows-Kernel-File /ge:true` manifest on a real
# windows-latest runner, 0x11F0 leaves WRITE (0x200), DELETE_PATH (0x400) and RENAME_SETLINK_PATH
# (0x800) CLEAR. A keyword mask is a SILENT filter -- `logman update trace` exits 0 whatever the
# mask is, and an event whose keyword bit is clear is simply never written -- so the parser carried
# correct handlers for events 26/27/28 that could never fire, and the trace still looked healthy
# (EventsLost 0, tens of thousands of events, a plausible path set).
#
# Those three events are the ONLY carriers of a DESTINATION path: a rename's new name, a hard
# link's new name, a delete's resolved path. Measured on the known-answer fixture at 0x11F0, the
# rename destination and the hardlink destination were ABSENT ENTIRELY from the normalized stream
# -- a write the tracer cannot see becomes a capability the synthesized grant omits, which is the
# direction that breaks a user's install.
#
# 0x1FF0 is every keyword the provider declares (their OR is exactly 0x1FF0), so there is nothing
# further to enable here. Widening the mask ALONE is inert: the decoder resolved a handle op's path
# from the FileObject, which on a RenamePath still names the SOURCE, so the source won even once the
# destination arrived. See `windows.mjs`'s DEST_PATH_EVENTS -- the two halves must move together.
#
# CREATE and OP_END are the load-bearing pair: Create carries the path and the disposition, and the
# matching OperationEnd carries the NTSTATUS that says whether it was refused. FILEIO is kept
# despite its volume because it is the only source of the Write event, which is what catches a
# write through a plain non-mutating open (see windows.mjs).
#
# Sequential file mode, not circular: a circular buffer silently overwrites the START of the trace,
# which is exactly where a postinstall's first writes are.
# ---------------------------------------------------------------------------------------------
& logman stop $Session -ets 2>&1 | Out-Null
& logman create trace $Session -ets -o $etl -bs 1024 -nb 64 320 -max $MaxMB | Out-Null
if ($LASTEXITCODE -ne 0) { throw "logman create trace failed with $LASTEXITCODE" }
# ONE literal, used by the session AND by the meta that claims what the session enabled. Two copies
# would let the recorded provenance drift away from the actual mask, and a meta that lies about its
# mask is worse than one that omits it -- the whole point of recording it is to be trusted later.
$fileMask = '0x1FF0'
& logman update trace $Session -ets -p 'Microsoft-Windows-Kernel-File'    $fileMask 5 | Out-Null
$fileMaskExit = $LASTEXITCODE
& logman update trace $Session -ets -p 'Microsoft-Windows-Kernel-Network' 0x30   5 | Out-Null
& logman update trace $Session -ets -p 'Microsoft-Windows-Kernel-Process' 0x10   5 | Out-Null
Start-Sleep -Milliseconds $SettleMs

# ---------------------------------------------------------------------------------------------
# The run. cmd.exe is the root of the subtree; every event we keep descends from this PID.
#
# The exit code is written here from Process.ExitCode. A scheduled task's LastTaskResult is the
# SHELL's exit code and not the program's, which is why nothing on this box uses schtasks.
# ---------------------------------------------------------------------------------------------
$started = (Get-Date).ToUniversalTime().ToString('o')
$p = Start-Process -FilePath $env:ComSpec -ArgumentList "/c $Command" -WorkingDirectory $WorkDir `
  -NoNewWindow -PassThru `
  -RedirectStandardOutput (Join-Path $OutDir 'run.out') `
  -RedirectStandardError  (Join-Path $OutDir 'run.err')
$rootPid = $p.Id
# Touching .Handle caches the process handle. Without it ExitCode comes back EMPTY once the child
# has exited, and an empty exit code reads exactly like a zero.
$null = $p.Handle
$p.WaitForExit()
$exitCode = $p.ExitCode
$ended = (Get-Date).ToUniversalTime().ToString('o')

Start-Sleep -Milliseconds $SettleMs
& logman stop $Session -ets | Out-Null

# ---------------------------------------------------------------------------------------------
# Convert. tracerpt decodes the manifest providers into named fields; -lr keeps events whose
# payload does not match the schema instead of dropping them.
# ---------------------------------------------------------------------------------------------
& tracerpt $etl -o $xml -of XML -summary $sum -lr -y | Out-Null
$tracerptExit = $LASTEXITCODE

# Events Lost is the integrity gate. A trace that dropped events cannot answer "no more than this".
$lost = -1
$processed = -1
foreach ($line in (Get-Content $sum)) {
  if ($line -match 'Total Events\s+Lost\s+(\d+)')      { $lost = [int]$Matches[1] }
  if ($line -match 'Total Events\s+Processed\s+(\d+)') { $processed = [int]$Matches[1] }
}

$meta = [ordered]@{
  schema        = 'nub-obs-win/1'
  whoami        = $id.Name
  sid           = $id.User.Value
  elevated      = $elevated
  privDropped   = $dropped
  host          = $env:COMPUTERNAME
  os            = [System.Environment]::OSVersion.VersionString
  command       = $Command
  workDir       = $WorkDir
  rootPid       = $rootPid
  launcherPid   = $PID
  exitCode      = $exitCode
  startedUtc    = $started
  endedUtc      = $ended
  userProfile   = $env:USERPROFILE
  temp          = $env:TEMP
  devmap        = $devmap
  eventsLost    = $lost
  eventsTotal   = $processed
  tracerptExit  = $tracerptExit
  # PROVENANCE, not decoration. A stream is only as complete as the keyword mask that produced it,
  # and 0x11F0 vs 0x1FF0 is the difference between having rename/hardlink destinations and silently
  # not having them. A retained record whose meta does not name its mask cannot be re-read later
  # with any confidence about what it is missing.
  fileMask      = $fileMask
  fileMaskExit  = $fileMaskExit
}
$meta | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $OutDir 'meta.json') -Encoding Ascii

Write-Output "CAPTURE user=$($id.Name) elevated=$elevated rootPid=$rootPid exit=$exitCode events=$processed lost=$lost"
if ($lost -gt 0) { Write-Output "CAPTURE-WARNING $lost events lost; this trace cannot support an exact-set claim" }
