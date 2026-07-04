<#
  bsod-forensics installer - github.com/varelaia/bsod-forensics

  Installs:
    1. The "bsod-forensics" skill for Claude Code -> %USERPROFILE%\.claude\skills\bsod-forensics\
    2. Get-BsodCulprit.ps1 (bundled inside the skill folder, usable standalone)
    3. WinDbg via winget (only if no debugger is present)
    4. _NT_SYMBOL_PATH user env var + C:\Symbols (only if not already set)

  Two install modes (same file):
    a) one-liner:  irm https://raw.githubusercontent.com/varelaia/bsod-forensics/main/install.ps1 | iex
    b) clone:      git clone ... ; .\install.ps1   (uses the local files)

  Env knobs (set before running):
    BSOD_NO_WINDBG=1       skip the WinDbg check/install
    BSOD_NO_SYMBOLPATH=1   do not touch _NT_SYMBOL_PATH

  Idempotent: re-running updates the skill files and never duplicates config.
  Rollback: see README (delete the skill folder, optionally remove the env var).

  ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less scripts as ANSI
  and non-ASCII characters break parsing.
#>

$ErrorActionPreference = 'Stop'

function Write-Info($msg) { Write-Host ("  -> " + $msg) -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host ("  OK " + $msg) -ForegroundColor Green }
function Write-Wrn($msg)  { Write-Host ("  !  " + $msg) -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host ("  X  " + $msg) -ForegroundColor Red }

$RepoRaw  = 'https://raw.githubusercontent.com/varelaia/bsod-forensics/main'
$SkillDir = Join-Path $env:USERPROFILE '.claude\skills\bsod-forensics'
$Files = @(
  @{ Rel = 'skill/bsod-forensics/SKILL.md';   Dest = (Join-Path $SkillDir 'SKILL.md') },
  @{ Rel = 'scripts/Get-BsodCulprit.ps1';     Dest = (Join-Path $SkillDir 'scripts\Get-BsodCulprit.ps1') }
)

# Old TLS defaults on stock PS 5.1 break raw.githubusercontent.com.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

Write-Host 'bsod-forensics installer - BSOD forensics for Claude Code + PowerShell'

# Where am I running from? $PSScriptRoot is empty under "irm | iex".
$localRoot = $null
if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot 'skill\bsod-forensics\SKILL.md'))) {
  $localRoot = $PSScriptRoot
  Write-Ok 'local clone detected - installing from local files'
} else {
  Write-Ok 'no local clone - fetching files from GitHub (irm|iex mode)'
}

# 1) plant the skill + script
foreach ($f in $Files) {
  $destDir = Split-Path $f.Dest -Parent
  if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
  if ($localRoot) {
    Copy-Item (Join-Path $localRoot ($f.Rel -replace '/', '\')) $f.Dest -Force
  } else {
    $url = $RepoRaw + '/' + $f.Rel
    try {
      Invoke-WebRequest -Uri $url -OutFile $f.Dest -UseBasicParsing
    } catch {
      Write-Err ('could not fetch ' + $url)
      Write-Err $_.Exception.Message
      exit 1
    }
  }
  Write-Ok ('installed ' + $f.Dest)
}

# 2) debugger present?
if ($env:BSOD_NO_WINDBG -eq '1') {
  Write-Wrn 'BSOD_NO_WINDBG=1 - skipping the WinDbg check.'
} else {
  $hasDbg = $false
  $cdb86 = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64\cdb.exe'
  if (Test-Path $cdb86) { $hasDbg = $true; Write-Ok ('debugger found: ' + $cdb86) }
  if (-not $hasDbg) {
    $wdx = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\WinDbgX.exe'
    if ((Test-Path $wdx) -or (Get-Command WinDbgX.exe -ErrorAction SilentlyContinue)) {
      $hasDbg = $true; Write-Ok 'debugger found: WinDbgX (winget app)'
    }
  }
  if (-not $hasDbg) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
      Write-Info 'no debugger found - installing WinDbg via winget (this is the one system change)...'
      winget install Microsoft.WinDbg --accept-source-agreements --accept-package-agreements
      if ($LASTEXITCODE -ne 0) {
        Write-Wrn 'winget install returned non-zero - install manually: winget install Microsoft.WinDbg'
      } else {
        Write-Ok 'WinDbg installed'
      }
    } else {
      Write-Wrn 'no winget available - install WinDbg manually from the Microsoft Store (search "WinDbg").'
    }
  }
}

# 3) symbol path (user-level, only if absent - never clobbers an existing one)
if ($env:BSOD_NO_SYMBOLPATH -eq '1') {
  Write-Wrn 'BSOD_NO_SYMBOLPATH=1 - not touching _NT_SYMBOL_PATH.'
} else {
  $current = [Environment]::GetEnvironmentVariable('_NT_SYMBOL_PATH', 'User')
  if ($current) {
    Write-Ok ('_NT_SYMBOL_PATH already set (respecting it): ' + $current)
  } else {
    $symPath = 'srv*C:\Symbols*https://msdl.microsoft.com/download/symbols'
    [Environment]::SetEnvironmentVariable('_NT_SYMBOL_PATH', $symPath, 'User')
    if (-not (Test-Path 'C:\Symbols')) {
      try { New-Item -ItemType Directory -Path 'C:\Symbols' -Force | Out-Null } catch {
        Write-Wrn 'could not create C:\Symbols (non-admin?) - WinDbg will create it on first use.'
      }
    }
    Write-Ok ('_NT_SYMBOL_PATH set (user) = ' + $symPath)
  }
}

Write-Host ''
Write-Host '  Done. Two ways to use it:'
Write-Host '    A) Claude Code (agent mode): open claude on this machine and say'
Write-Host '       "analyze my BSOD" - the bsod-forensics skill drives the whole flow.'
Write-Host '    B) Standalone (no AI): from an elevated PowerShell:'
Write-Host ('       powershell -ExecutionPolicy Bypass -File "' + (Join-Path $SkillDir 'scripts\Get-BsodCulprit.ps1') + '"')
Write-Host ''
Write-Host '  Rollback: Remove-Item -Recurse "' -NoNewline
Write-Host ($SkillDir + '"')
