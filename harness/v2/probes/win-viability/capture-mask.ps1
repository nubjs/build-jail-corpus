# A capture identical to `adapters/windows.ps1` except that the Kernel-File KEYWORD MASK is a
# parameter. It exists for one experiment and should not outlive it.
#
# ⛔ THE EXPERIMENT: the shipped adapter enables `0x11F0`, and its own comment names nine keywords
# for it. MEASURED against the provider's manifest on a real runner, `0x11F0` carries six of those
# nine -- `WRITE` (0x200), `DELETE_PATH` (0x400) and `RENAME_SETLINK_PATH` (0x800) are NOT in it, and
# the mask that would carry all nine is `0x1FF0`. Running one fixture at both masks, changing nothing
# else, is what converts "the mask looks wrong" into "here is exactly what it loses".
#
# ⛔ A SEPARATE FILE RATHER THAN A PARAMETER ON THE SHIPPED ADAPTER. `windows.ps1` is what every
# existing Windows measurement went through; adding a knob to it mid-probe would mean the baseline
# arm and the experimental arm no longer share a code path with anything already recorded.
#
# Everything else -- the privilege drop, the device map, the sequential file mode, the buffer
# configuration, the meta.json schema windows.mjs consumes -- is kept byte-for-byte equivalent, so
# the mask is genuinely the only variable.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$OutDir,
  [Parameter(Mandatory = $true)][string]$Command,
  [string]$WorkDir = (Get-Location).Path,
  [string]$Session = 'nubmask',
  [string]$FileMask = '0x11F0',
  [int]$MaxMB = 8192,
  [int]$SettleMs = 1200
)

$ErrorActionPreference = 'Stop'

# Same DACL-bypass privilege removal as the shipped adapter: an elevated token carries
# SeBackupPrivilege, libuv sets FILE_FLAG_BACKUP_SEMANTICS on every open, and together they bypass
# the DACL outright -- so a package that probes, is refused, and falls back would be observed taking
# the probe and never the fallback.
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
  tp.Privilege.Attributes = 0x00000004;
  if (!AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return "AdjustTokenPrivileges:" + Marshal.GetLastWin32Error();
  int e = Marshal.GetLastWin32Error();
  return (e == 1300) ? "already-absent" : "removed";
}
'@
$tokTypes = Add-Type -MemberDefinition $tokSrc -Name 'NubMaskTok' -Namespace 'NubObsMask' -PassThru
$Tok = @($tokTypes) | Where-Object { $_.Name -eq 'NubMaskTok' }
$dropped = [ordered]@{}
foreach ($priv in 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege') {
  $dropped[$priv] = $Tok::Drop($priv)
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$id).IsInRole(544)
if (-not $elevated) { throw "capture-mask.ps1 needs an elevated token; ETW kernel providers are admin-only" }
if ($id.User.Value -eq 'S-1-5-18') { throw "refusing to trace as SYSTEM ($($id.Name))" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$etl = Join-Path $OutDir 'trace.etl'
$xml = Join-Path $OutDir 'trace.xml'
$sum = Join-Path $OutDir 'summary.txt'
Remove-Item $etl, $xml, $sum -Force -ErrorAction SilentlyContinue

$sig = @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, uint ucchMax);
'@
$k32 = Add-Type -MemberDefinition $sig -Name 'NubMaskDosDev' -Namespace 'NubObsMask' -PassThru
$devmap = @{}
foreach ($ch in [char[]]([char]'A'..[char]'Z')) {
  $sb = New-Object System.Text.StringBuilder 2048
  if ($k32::QueryDosDevice("$ch`:", $sb, 2048) -gt 0) {
    $target = $sb.ToString()
    if ($target) { $devmap[$target] = "$ch`:" }
  }
}

& logman stop $Session -ets 2>&1 | Out-Null
& logman create trace $Session -ets -o $etl -bs 1024 -nb 64 320 -max $MaxMB | Out-Null
if ($LASTEXITCODE -ne 0) { throw "logman create trace failed with $LASTEXITCODE" }
& logman update trace $Session -ets -p 'Microsoft-Windows-Kernel-File'    $FileMask 5 | Out-Null
$fileMaskExit = $LASTEXITCODE
& logman update trace $Session -ets -p 'Microsoft-Windows-Kernel-Network' 0x30   5 | Out-Null
& logman update trace $Session -ets -p 'Microsoft-Windows-Kernel-Process' 0x10   5 | Out-Null
Start-Sleep -Milliseconds $SettleMs

$started = (Get-Date).ToUniversalTime().ToString('o')
$p = Start-Process -FilePath $env:ComSpec -ArgumentList "/c $Command" -WorkingDirectory $WorkDir `
  -NoNewWindow -PassThru `
  -RedirectStandardOutput (Join-Path $OutDir 'run.out') `
  -RedirectStandardError  (Join-Path $OutDir 'run.err')
$rootPid = $p.Id
$null = $p.Handle
$p.WaitForExit()
$exitCode = $p.ExitCode
$ended = (Get-Date).ToUniversalTime().ToString('o')

Start-Sleep -Milliseconds $SettleMs
# The live session's own counters, read BEFORE the stop. This is the kernel's account of loss and is
# independent of the tracerpt summary the shipped adapter scrapes.
$live = (& logman query $Session -ets 2>&1 | Out-String)
Set-Content -Path (Join-Path $OutDir 'logman-query.txt') -Value $live -Encoding Ascii
& logman stop $Session -ets | Out-Null

& tracerpt $etl -o $xml -of XML -summary $sum -lr -y | Out-Null
$tracerptExit = $LASTEXITCODE

$lost = -1; $processed = -1
foreach ($line in (Get-Content $sum)) {
  if ($line -match 'Total Events\s+Lost\s+(\d+)')      { $lost = [int]$Matches[1] }
  if ($line -match 'Total Events\s+Processed\s+(\d+)') { $processed = [int]$Matches[1] }
}
$liveLost = -1; $liveBuffersLost = -1
foreach ($line in ($live -split "`r?`n")) {
  if ($line -match 'Events Lost:\s*(\d+)')  { $liveLost = [int]$Matches[1] }
  if ($line -match 'Buffers Lost:\s*(\d+)') { $liveBuffersLost = [int]$Matches[1] }
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
  fileMask      = $FileMask
  fileMaskExit  = $fileMaskExit
  liveEventsLost   = $liveLost
  liveBuffersLost  = $liveBuffersLost
  etlBytes      = (Get-Item $etl -ErrorAction SilentlyContinue).Length
  xmlBytes      = (Get-Item $xml -ErrorAction SilentlyContinue).Length
}
$meta | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $OutDir 'meta.json') -Encoding Ascii

Write-Output ("CAPTURE-MASK mask=$FileMask (logman rc=$fileMaskExit) rootPid=$rootPid exit=$exitCode " +
  "events=$processed tracerptLost=$lost logmanEventsLost=$liveLost logmanBuffersLost=$liveBuffersLost")
