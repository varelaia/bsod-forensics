<p align="center"><img src="assets/banner.svg" alt="bsod-forensics — Varela Insights" width="100%"></p>
<p align="center">
  <img src="https://img.shields.io/badge/windows-WinDbg%20%C2%B7%20PowerShell-0a0e1a?style=flat-square" alt="Windows">
  <img src="https://img.shields.io/badge/license-MIT-22c55e?style=flat-square" alt="MIT">
  <a href="https://www.varelainsights.com/"><img src="https://img.shields.io/badge/by-Varela%20Insights-6aa0ff?style=flat-square" alt="Varela Insights"></a>
</p>

# bsod-forensics

**Find the exact driver behind a Windows blue screen — in minutes, not days.**

[Español](README.es.md)

A BSOD leaves a bugcheck code (`0x3b`, `0x1a`, …) in the Event Viewer, and that code is
where most diagnoses stop — usually at *"probably bad RAM"*. But the code is not the
diagnosis. The **culprit driver and function live inside the crash dump**, and WinDbg's
`!analyze -v` names them explicitly. This repo automates that flow:

- a **PowerShell script** (`Get-BsodCulprit.ps1`) that locates the dump, runs the analysis
  and prints the culprit + evidence + prioritized leads — no debugging knowledge needed;
- a **[Claude Code](https://claude.com/claude-code) skill** that teaches the agent the full
  forensic method (when to suspect a driver vs. RAM vs. thermal, the red flags, the traps);
- a **[real case study](case-studies/dxgkrnl-iswsl2guest/)** where a crash that looked
  exactly like flaky RAM turned out to be a named, reproducible driver bug.

## Quick start

From PowerShell (no admin needed to install):

```powershell
irm https://raw.githubusercontent.com/varelaia/bsod-forensics/main/install.ps1 | iex
```

What it does (idempotent — safe to re-run):

1. Plants the `bsod-forensics` skill in `%USERPROFILE%\.claude\skills\` (for Claude Code users).
2. Installs `Get-BsodCulprit.ps1` inside the skill folder (works standalone, no AI required).
3. Installs **WinDbg** via `winget` — only if no debugger is present. Skip with `BSOD_NO_WINDBG=1`.
4. Sets `_NT_SYMBOL_PATH` (user env var) — only if not already set. Skip with `BSOD_NO_SYMBOLPATH=1`.

Or clone and run the same installer locally:

```powershell
git clone https://github.com/varelaia/bsod-forensics
cd bsod-forensics
.\install.ps1
```

## Usage

### A) Standalone script (no AI)

From an **elevated** PowerShell (needed to read dumps under `C:\Windows`):

```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude\skills\bsod-forensics\scripts\Get-BsodCulprit.ps1"
```

Or point it at a dump you copied out (no admin needed), or at a saved analysis log:

```powershell
Get-BsodCulprit.ps1 -DumpPath C:\dumps\MEMORY.DMP
Get-BsodCulprit.ps1 -FromLog .\analysis.txt      # offline, no debugger involved
```

Real output (from the case study in this repo):

```
=== BSOD FORENSICS ============================================
  BugCheck  : 0x3b SYSTEM_SERVICE_EXCEPTION
  CULPRIT   : dxgkrnl.sys
  Function  : dxgkrnl!DXGVIRTUALMACHINE::IsWsl2Guest+0
  Bucket    : AV_dxgkrnl!DXGVIRTUALMACHINE::IsWsl2Guest   <- search this string online
  Process   : vmwp.exe
  Verdict   : Named software module -> driver/component bug is the working
              hypothesis, NOT random hardware.
  Next steps (do NOT execute blindly - they are leads):
    1. Update or roll back the driver that owns dxgkrnl.sys.
    2. Search the web for the FAILURE_BUCKET_ID above.
    ...
===============================================================
```

### B) Claude Code (agent mode)

With the skill installed, just tell Claude Code on the affected machine:

> "my PC blue-screened, find out why" / "analyze the BSOD"

The skill drives the whole flow — checking dump policy, running the script, reading the
evidence — and enforces the method's iron rule: **no cause is asserted without opening
the dump**.

## The demo case: `dxgkrnl!IsWsl2Guest`

A Dell workstation blue-screened 3 times in 3 days with `0x3b SYSTEM_SERVICE_EXCEPTION` —
mixed RAM sticks made "bad RAM" the obvious suspect. The dump named the real culprit in
minutes: a **null-pointer dereference in the WSL2 GPU-PV cleanup path** (`dxgkrnl.sys`),
triggered every time the machine shut down with WSL2 running. Same instruction offset all
3 times = reproducible driver bug, **not** hardware. RAM would have been replaced for nothing.

Full walkthrough with the raw WinDbg output: [case-studies/dxgkrnl-iswsl2guest/](case-studies/dxgkrnl-iswsl2guest/)

## Requirements

- Windows 10/11, Windows PowerShell 5.1+ (preinstalled).
- `winget` (preinstalled on current Windows) if WinDbg needs installing.
- Internet access on first analysis (Microsoft symbol download).
- An elevated shell **only** to read dumps under `C:\Windows` (auto-locate mode).

## Honest limitations

- **One demo case (N=1).** The method is standard WinDbg forensics; our evidence that it
  beats blind diagnosis is one thoroughly documented case, not a statistic.
- **No dump, no forensics.** A hard freeze with `CrashDumpEnabled=0` leaves nothing to
  analyze; the script tells you how to enable minidumps for the *next* crash.
- **WinDbgX opens a UI window** during analysis (it closes itself). Fully headless analysis
  requires `cdb.exe` from the Windows SDK Debugging Tools, which the script prefers when present.
- Big dumps + first symbol download can take several minutes. That is normal.
- The verdict is a **prioritized working hypothesis with evidence**, not an oracle.

## Rollback

```powershell
Remove-Item -Recurse "$env:USERPROFILE\.claude\skills\bsod-forensics"
# optional: remove the symbol path if the installer set it
[Environment]::SetEnvironmentVariable('_NT_SYMBOL_PATH', $null, 'User')
# optional: winget uninstall Microsoft.WinDbg
```

## Roadmap

- **v1.0** — `bsod-forensics`: BSOD culprit identification + WSL2 GPU-PV case study. *(this release)*
- **v1.1** — `host-sentinel`: continuous evidence capture (SQLite collector) for machines
  that fail intermittently, so no crash goes unrecorded.
- **v1.2** — more failure classes: app crashes (Event 1000/1002), WebView2/Electron patterns.
- **v2.0** — relaunch as the **`windows-diagnostics`** suite: capture + forensics, one install.

## License

[MIT](LICENSE)
