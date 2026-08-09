$ErrorActionPreference = 'Stop'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
  throw "Visual Studio locator is absent: $vswhere"
}

$installation = & $vswhere -latest -products '*' `
  -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
  -property installationPath | Select-Object -First 1
$installation = "$installation".Trim()
if (-not $installation) {
  throw 'No Visual Studio installation with the x64 C++ toolchain was found'
}

$devCmd = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $devCmd)) {
  throw "Visual Studio developer command file is absent: $devCmd"
}

$lines = & $env:ComSpec /d /s /c "call `"$devCmd`" -no_logo -arch=x64 -host_arch=x64 >nul && set"
if ($LASTEXITCODE -ne 0) {
  throw "VsDevCmd failed with exit code $LASTEXITCODE"
}

$values = @{}
foreach ($line in $lines) {
  $separator = $line.IndexOf('=')
  if ($separator -le 0) { continue }
  $values[$line.Substring(0, $separator)] = $line.Substring($separator + 1)
}

# Only export variables the versioned reference profile is allowed to inherit. In particular, do
# not leak credentials or the rest of the hosted runner environment into third-party scripts.
$required = @('Path', 'INCLUDE', 'LIB', 'LIBPATH', 'VCINSTALLDIR', 'VSINSTALLDIR',
  'WindowsSdkDir', 'VCToolsInstallDir', 'UCRTVersion', 'WindowsSDKVersion')
foreach ($name in $required) {
  if (-not $values.ContainsKey($name) -or -not $values[$name]) {
    throw "VsDevCmd did not define required environment variable $name"
  }
  "$name=$($values[$name])" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
}

# Git for Windows prepends its POSIX tool directory when it starts bash, so an unqualified
# `link.exe` resolves to `/usr/bin/link` even though VsDevCmd put MSVC first in the Windows PATH.
# Cargo's target-specific override is build plumbing only; reference profiles intentionally do not
# inherit it into third-party lifecycle scripts.
$linker = Join-Path $values['VCToolsInstallDir'] 'bin\HostX64\x64\link.exe'
if (-not (Test-Path $linker -PathType Leaf)) {
  throw "MSVC linker is absent: $linker"
}
"CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=$linker" |
  Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append

Write-Host "Activated MSVC from $installation with linker $linker"
