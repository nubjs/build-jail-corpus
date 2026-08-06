# Build the known-answer fixture. Everything the fixture touches lives under C:\obs\fx so the
# validator can make an EXACT-SET assertion inside a namespace we fully control.
$ErrorActionPreference = 'Stop'
$root = 'C:\obs\fx'
Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
  try { $a = Get-Acl $_.FullName; $a.SetAccessRuleProtection($false,$true); Set-Acl $_.FullName $a } catch {}
}
Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "$root\proj" | Out-Null
New-Item -ItemType Directory -Force -Path "$root\denied" | Out-Null
Remove-Item "$env:USERPROFILE\fx-userprofile-write.txt" -Force -ErrorAction SilentlyContinue

# A file the fixture READS and never writes.
Set-Content -Path "$root\proj\read-only-input.txt" -Value "input" -Encoding Ascii
# A file the fixture NEVER touches at all. False-negative control: it must not appear anywhere.
Set-Content -Path "$root\proj\never-touched.txt" -Value "decoy" -Encoding Ascii

# A directory the interactive user cannot write. An explicit Deny ACE on the user's own SID beats
# the Administrators grant the token also carries, so this refuses even from an elevated shell.
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = Get-Acl "$root\denied"
$acl.SetAccessRuleProtection($true, $true)
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
  $sid, 'Write,CreateFiles,CreateDirectories,Delete,Modify', 'ContainerInherit,ObjectInherit', 'None', 'Deny')))
Set-Acl -Path "$root\denied" -AclObject $acl

# Prove the denial is real from THIS security context before we trust the trace. A negative
# control that cannot fire is not a control.
try {
  [IO.File]::WriteAllText("$root\denied\control.txt", 'x')
  Write-Output "FIXTURE-PRECHECK: FAIL - the denied dir is writable, the negative control is dead"
} catch [System.UnauthorizedAccessException] {
  Write-Output "FIXTURE-PRECHECK: ok - denied dir refuses writes as $env:USERNAME"
} catch {
  Write-Output "FIXTURE-PRECHECK: UNEXPECTED $($_.Exception.GetType().FullName)"
}
Write-Output "FIXTURE-USER: $(whoami)"
