<#
.SYNOPSIS
  Finds the culprit driver/module behind a Windows BSOD by running
  WinDbg "!analyze -v" on a crash dump and parsing the result.

.DESCRIPTION
  Automates the flow: locate dump -> ensure symbols -> run !analyze -v
  (WinDbgX or cdb) -> parse MODULE_NAME / SYMBOL_NAME / FAILURE_BUCKET_ID
  -> print the culprit, the evidence and prioritized next steps.

  Compatible with Windows PowerShell 5.1 (powershell.exe). ASCII-only on
  purpose: PS 5.1 reads BOM-less scripts as ANSI and non-ASCII characters
  break parsing.

.PARAMETER DumpPath
  Path to a specific .dmp / .DMP file. If omitted, the newest dump is
  auto-located from C:\Windows\Minidump\*.dmp and C:\Windows\MEMORY.DMP
  (requires an elevated shell to read C:\Windows).

.PARAMETER FromLog
  Skip the debugger entirely and parse an existing "!analyze -v" output
  file (e.g. a saved analysis.txt). Useful offline and for testing.

.PARAMETER OutDir
  Where to store the raw analysis log. Default: $env:USERPROFILE\bsod-forensics

.PARAMETER SymbolPath
  Override the symbol path. Default: existing _NT_SYMBOL_PATH, or
  srv*C:\Symbols*https://msdl.microsoft.com/download/symbols

.PARAMETER TimeoutMinutes
  Max minutes to wait for the debugger (symbol download can be slow). Default 15.

.EXAMPLE
  .\Get-BsodCulprit.ps1
  .\Get-BsodCulprit.ps1 -DumpPath C:\dumps\MEMORY.DMP
  .\Get-BsodCulprit.ps1 -FromLog .\analysis.txt

.NOTES
  Exit codes: 0 = culprit parsed, 1 = no dump found, 2 = no debugger,
  3 = debugger ran but output could not be parsed.
#>
[CmdletBinding()]
param(
  [string]$DumpPath,
  [string]$FromLog,
  [string]$OutDir = (Join-Path $env:USERPROFILE 'bsod-forensics'),
  [string]$SymbolPath,
  [int]$TimeoutMinutes = 15
)

$ErrorActionPreference = 'Stop'

# --- helpers -----------------------------------------------------------------

function Write-Info($msg)  { Write-Host ("  -> " + $msg) -ForegroundColor Cyan }
function Write-Ok($msg)    { Write-Host ("  OK " + $msg) -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host ("  !  " + $msg) -ForegroundColor Yellow }
function Write-Err($msg)   { Write-Host ("  X  " + $msg) -ForegroundColor Red }

$BugcheckNames = @{
  '1a'  = 'MEMORY_MANAGEMENT'
  '3b'  = 'SYSTEM_SERVICE_EXCEPTION'
  '50'  = 'PAGE_FAULT_IN_NONPAGED_AREA'
  '4e'  = 'PFN_LIST_CORRUPT'
  '7e'  = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'
  'd1'  = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL'
  'a'   = 'IRQL_NOT_LESS_OR_EQUAL'
  'ef'  = 'CRITICAL_PROCESS_DIED'
  '101' = 'CLOCK_WATCHDOG_TIMEOUT (CPU/thermal suspect)'
  '124' = 'WHEA_UNCORRECTABLE_ERROR (hardware suspect)'
  '133' = 'DPC_WATCHDOG_VIOLATION'
  '139' = 'KERNEL_SECURITY_CHECK_FAILURE'
  '9f'  = 'DRIVER_POWER_STATE_FAILURE'
}

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-NewestDump {
  # Returns the newest dump among minidumps and the kernel MEMORY.DMP.
  $candidates = @()
  $miniDir = Join-Path $env:SystemRoot 'Minidump'
  if (Test-Path $miniDir) {
    $candidates += Get-ChildItem -Path $miniDir -Filter '*.dmp' -ErrorAction SilentlyContinue
  }
  $memDmp = Join-Path $env:SystemRoot 'MEMORY.DMP'
  if (Test-Path $memDmp) {
    $candidates += Get-Item $memDmp -ErrorAction SilentlyContinue
  }
  if ($candidates.Count -eq 0) { return $null }
  $sorted = $candidates | Sort-Object LastWriteTime -Descending
  if ($sorted.Count -gt 1) {
    Write-Info ("dumps found: " + $sorted.Count + " (analyzing the newest; older ones listed below)")
    $sorted | Select-Object -Skip 1 | ForEach-Object {
      Write-Host ("       " + $_.FullName + "  (" + $_.LastWriteTime + ")")
    }
  }
  return $sorted[0]
}

function Find-Debugger {
  # Prefer cdb.exe (true console debugger), fall back to WinDbgX (winget app).
  $cdbCandidates = @(
    (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64\cdb.exe'),
    (Join-Path $env:ProgramFiles       'Windows Kits\10\Debuggers\x64\cdb.exe')
  )
  foreach ($c in $cdbCandidates) {
    if ($c -and (Test-Path $c)) { return @{ Kind = 'cdb'; Path = $c } }
  }
  $winDbgX = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\WinDbgX.exe'
  if (Test-Path $winDbgX) { return @{ Kind = 'windbgx'; Path = $winDbgX } }
  $cmd = Get-Command WinDbgX.exe -ErrorAction SilentlyContinue
  if ($cmd) { return @{ Kind = 'windbgx'; Path = $cmd.Source } }
  return $null
}

function Invoke-Analyze {
  param($Debugger, [string]$Dump, [string]$LogFile, [string]$Symbols, [int]$TimeoutMin)

  if (Test-Path $LogFile) { Remove-Item $LogFile -Force }
  $env:_NT_SYMBOL_PATH = $Symbols

  if ($Debugger.Kind -eq 'cdb') {
    # cdb prints to stdout; qd quits without saving a workspace.
    $cmds = '!analyze -v; qd'
    Write-Info ("running cdb !analyze -v (symbol download can take minutes)...")
    $p = Start-Process -FilePath $Debugger.Path `
      -ArgumentList @('-z', ('"' + $Dump + '"'), '-c', ('"' + $cmds + '"')) `
      -RedirectStandardOutput $LogFile -NoNewWindow -PassThru
  } else {
    # WinDbgX is a UI app but honors -c; .logopen captures the session.
    $cmds = '.logopen ' + $LogFile + '; !analyze -v; .logclose; qd'
    Write-Info ("running WinDbgX !analyze -v (a window opens and closes itself; symbol download can take minutes)...")
    $p = Start-Process -FilePath $Debugger.Path `
      -ArgumentList @('-z', ('"' + $Dump + '"'), '-c', ('"' + $cmds + '"')) -PassThru
  }

  if (-not $p.WaitForExit($TimeoutMin * 60 * 1000)) {
    Write-Warn2 ("debugger still running after " + $TimeoutMin + " min - killing it. Re-run with -TimeoutMinutes 30 for big dumps.")
    try { $p.Kill() } catch {}
  }
  # WinDbgX sometimes exits before the log is flushed; give it a moment.
  $tries = 0
  while (-not (Test-Path $LogFile) -and $tries -lt 10) { Start-Sleep -Seconds 1; $tries++ }
}

function Parse-Analysis {
  param([string]$Text)
  # Tolerant field extraction: every field is optional; report what exists.
  $r = @{}
  if ($Text -match '(?m)^BUGCHECK_CODE:\s+([0-9a-fA-F]+)') { $r.Code = $Matches[1].ToLower() }
  foreach ($i in 1..4) {
    if ($Text -match ('(?m)^BUGCHECK_P' + $i + ':\s+(\S+)')) { $r.('P' + $i) = $Matches[1] }
  }
  if ($Text -match '(?m)^MODULE_NAME:\s*(\S+)')       { $r.Module = $Matches[1] }
  if ($Text -match '(?m)^IMAGE_NAME:\s+(\S+)')        { $r.Image = $Matches[1] }
  if ($Text -match '(?m)^SYMBOL_NAME:\s+(\S+)')       { $r.Symbol = $Matches[1] }
  if ($Text -match '(?m)^FAILURE_BUCKET_ID:\s+(\S+)') { $r.Bucket = $Matches[1] }
  if ($Text -match '(?m)^PROCESS_NAME:\s+(\S+)')      { $r.Process = $Matches[1] }
  if ($Text -match '(?m)^OSNAME:\s+(.+)$')            { $r.OsName = $Matches[1].Trim() }
  if ($Text -match '(?m)^OS_VERSION:\s+(\S+)')        { $r.OsVersion = $Matches[1] }
  $r.ChecksumMismatch = ($Text -match 'Check Image - Checksum mismatch')

  # First human-readable line, e.g. "SYSTEM_SERVICE_EXCEPTION (3b)"
  if ($Text -match '(?m)^([A-Z][A-Z0-9_]+)\s+\(([0-9a-fA-F]+)\)\s*$') {
    $r.CodeName = $Matches[1]
    if (-not $r.Code) { $r.Code = $Matches[2].ToLower() }
  }

  # Top of STACK_TEXT: keep the symbolized frame names only.
  $stack = @()
  if ($Text -match '(?ms)^STACK_TEXT:\s*$(.*?)(?:\r?\n\r?\n|\Z)') {
    $lines = $Matches[1] -split '\r?\n'
    foreach ($ln in $lines) {
      if ($ln -match ':\s+(\S+![\S]+)\s*$') { $stack += $Matches[1] }
      elseif ($ln -match ':\s+(\S+!\S+)\+0x[0-9a-fA-F]+\s*$') { $stack += $Matches[1] }
      if ($stack.Count -ge 8) { break }
    }
  }
  $r.Stack = $stack
  return $r
}

function Get-Verdict {
  param($R)
  $hw = @('124','101')
  if ($R.Code -and ($hw -contains $R.Code)) {
    return 'Hardware-class bugcheck (WHEA/clock). Check CPU/thermals/PSU; the dump names the reporter, not necessarily a driver.'
  }
  if ($R.Module -and $R.Module -ne 'Unknown_Module') {
    $v = 'Named software module -> driver/component bug is the working hypothesis, NOT random hardware.'
    $v += ' If repeated crashes hit the SAME instruction offset, it is a reproducible driver bug.'
    return $v
  }
  if ($R.Code -and (@('1a','50','4e') -contains $R.Code) -and -not $R.Module) {
    return 'Memory-class bugcheck with no consistent module named -> RAM becomes a real suspect. Vary of codes/offsets across dumps points to hardware; run MemTest86.'
  }
  return 'No module named by the analyzer - inspect the raw log and compare several dumps before blaming hardware.'
}

function Show-Report {
  param($R, [string]$Source, [string]$RawLog)

  $codeDisplay = '(unknown)'
  if ($R.Code) {
    $name = $R.CodeName
    if (-not $name -and $BugcheckNames.ContainsKey($R.Code)) { $name = $BugcheckNames[$R.Code] }
    if (-not $name) { $name = 'see raw log' }
    $codeDisplay = ('0x' + $R.Code + ' ' + $name)
  }

  Write-Host ''
  Write-Host '=== BSOD FORENSICS ============================================' -ForegroundColor White
  Write-Host ('  Source    : ' + $Source)
  Write-Host ('  BugCheck  : ' + $codeDisplay)
  if ($R.P1) { Write-Host ('  Args      : ' + $R.P1 + ' ' + $R.P2 + ' ' + $R.P3 + ' ' + $R.P4) }
  if ($R.Image -or $R.Module) {
    $culprit = $R.Image; if (-not $culprit) { $culprit = $R.Module }
    Write-Host ('  CULPRIT   : ' + $culprit) -ForegroundColor Red
  } else {
    Write-Host '  CULPRIT   : (not named - see verdict)' -ForegroundColor Yellow
  }
  if ($R.Symbol)  { Write-Host ('  Function  : ' + $R.Symbol) }
  if ($R.Bucket)  { Write-Host ('  Bucket    : ' + $R.Bucket + '   <- search this string online') }
  if ($R.Process) { Write-Host ('  Process   : ' + $R.Process) }
  if ($R.OsName)  { Write-Host ('  OS        : ' + $R.OsName + ' ' + $R.OsVersion) }
  if ($R.ChecksumMismatch) {
    Write-Warn2 'Checksum mismatch on a .sys reported -> on-disk binary may be corrupt/replaced (see next steps).'
  }
  if ($R.Stack.Count -gt 0) {
    Write-Host '  Stack (top):'
    $R.Stack | ForEach-Object { Write-Host ('    ' + $_) }
  }
  Write-Host ('  Verdict   : ' + (Get-Verdict $R))
  Write-Host ''
  Write-Host '  Next steps (do NOT execute blindly - they are leads):'
  $n = 1
  if ($R.Image -or $R.Module) {
    Write-Host ('    ' + $n + '. Update or roll back the driver that owns ' + $(if ($R.Image) { $R.Image } else { $R.Module }) + '.'); $n++
    Write-Host ('    ' + $n + '. Search the web for the FAILURE_BUCKET_ID above - known bugs surface fast.'); $n++
  }
  if ($R.ChecksumMismatch) {
    Write-Host ('    ' + $n + '. Run: sfc /scannow   and   DISM /Online /Cleanup-Image /RestoreHealth'); $n++
  }
  Write-Host ('    ' + $n + '. Keep every dump: same bucket N times = reproducible bug, not bad RAM.')
  if ($RawLog) { Write-Host ('  Raw log   : ' + $RawLog) }
  Write-Host '===============================================================' -ForegroundColor White
}

# --- main --------------------------------------------------------------------

Write-Host 'Get-BsodCulprit - BSOD forensics (github.com/varelaia/bsod-forensics)'

# Mode 1: parse an existing analysis log (offline / tests)
if ($FromLog) {
  if (-not (Test-Path $FromLog)) { Write-Err ('log not found: ' + $FromLog); exit 1 }
  $parsed = Parse-Analysis -Text (Get-Content $FromLog -Raw)
  if (-not $parsed.Code -and -not $parsed.Bucket) {
    Write-Err 'could not find bugcheck fields in that log - is it a "!analyze -v" output?'
    exit 3
  }
  Show-Report -R $parsed -Source $FromLog -RawLog $FromLog
  exit 0
}

# Mode 2: analyze a dump
if (-not $DumpPath) {
  if (-not (Test-IsAdmin)) {
    Write-Err 'auto-locating dumps under C:\Windows requires an ELEVATED shell.'
    Write-Err 'Either re-run as Administrator, or pass -DumpPath <copy of the dump>.'
    exit 1
  }
  $dump = Find-NewestDump
  if (-not $dump) {
    Write-Err 'no dump found (C:\Windows\Minidump empty and no MEMORY.DMP).'
    Write-Info 'check dump policy: (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl).CrashDumpEnabled'
    Write-Info 'value 0 = dumps disabled -> set to 3 (minidump), reboot, wait for the next BSOD.'
    exit 1
  }
  $DumpPath = $dump.FullName
}
if (-not (Test-Path $DumpPath)) { Write-Err ('dump not found: ' + $DumpPath); exit 1 }

$dbg = Find-Debugger
if (-not $dbg) {
  Write-Err 'no debugger found. Install WinDbg:  winget install Microsoft.WinDbg'
  exit 2
}
Write-Ok ('debugger: ' + $dbg.Kind + ' (' + $dbg.Path + ')')

if (-not $SymbolPath) {
  if ($env:_NT_SYMBOL_PATH) { $SymbolPath = $env:_NT_SYMBOL_PATH }
  else { $SymbolPath = 'srv*C:\Symbols*https://msdl.microsoft.com/download/symbols' }
}
Write-Ok ('symbols: ' + $SymbolPath)

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile = Join-Path $OutDir ('analysis-' + $stamp + '.txt')

Invoke-Analyze -Debugger $dbg -Dump $DumpPath -LogFile $logFile -Symbols $SymbolPath -TimeoutMin $TimeoutMinutes

if (-not (Test-Path $logFile)) {
  Write-Err 'debugger produced no output log - run it manually to see the error:'
  Write-Err ('  "' + $dbg.Path + '" -z "' + $DumpPath + '" -c "!analyze -v"')
  exit 3
}

$parsed = Parse-Analysis -Text (Get-Content $logFile -Raw)
if (-not $parsed.Code -and -not $parsed.Bucket) {
  Write-Err ('analysis ran but no bugcheck fields were parsed - inspect the raw log: ' + $logFile)
  exit 3
}
Show-Report -R $parsed -Source $DumpPath -RawLog $logFile
exit 0
