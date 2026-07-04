---
name: bsod-forensics
description: Windows crash-dump forensics (BSOD / blue screen). Use when a Windows machine reboots on its own, blue-screens, or reports a bugcheck 0xNN - to IDENTIFY THE CULPRIT DRIVER/MODULE by analyzing the dump with WinDbg `!analyze -v` (never stop at the 0xNN code). Triggers: "BSOD", "blue screen", "why does it crash / reboot by itself", "analyze the dump", "bugcheck 0x...", "MEMORY.DMP", "minidump", "0x3b / 0x1a / 0x124 / 0xd1". The trap it catches: diagnosing blind - blaming "hardware / RAM" - when the dump (same instruction offset repeated = reproducible driver bug) names the EXACT culprit in minutes. NOT for app crashes without a kernel bugcheck (that is Event Viewer / app logs) and NOT for Linux (journalctl / kdump / dmesg - different stack).
---

# bsod-forensics — identify the culprit behind a BSOD

## Principle
A BSOD leaves a `0xNN` (BugCheckCode) in the Event Viewer — but **the code does not name the
culprit**. The culprit (driver/module + function) lives **inside the dump** and is extracted with
`!analyze -v` + Microsoft symbols. Without that step every BSOD is a mystery diagnosed blind —
or worse, "it must be the RAM" and parts get replaced for no reason.

**Key dump insight:** if the SAME bugcheck happens **at the same instruction offset**
(`rip`, Arg2) N times, it is a **driver with a reproducible bug**, NOT random hardware failure.
That fingerprint (identical low offset bits across boots; only the ASLR base changes) is what
separates "software bug" from "flaky RAM".

## When it applies (and when it is something else)
| Situation | Tool |
|---|---|
| Kernel bugcheck (`0x3b`, `0x1a`, `0x50`, `0x124`, `0xd1`, `0x7e`…) → find the culprit | **bsod-forensics** (this skill) |
| App crash (no kernel bugcheck): app closes, Event 1000/1002 | Event Viewer / app logs, not a kernel dump |
| Machine freezes hard with NO dump written | fix dump policy first (see below), then wait for the next crash |
| Linux kernel panic | journalctl / kdump / dmesg — different stack |

## The iron rule
**Before asserting the cause of a BSOD, you opened the dump and read `FAILURE_BUCKET_ID` /
`SYMBOL_NAME`.** It is forbidden to:
- Say "it's the RAM" / "the PSU" / "thermal" without opening the dump.
- Stop at the `0xNN` ("a 0x3b means…") as if the code were the diagnosis.
- Rule hardware in or out WITHOUT checking whether the crash lands in a named software module.

Exception: if no dump was generated (`CrashDumpEnabled=0`) → there is no forensics of the past;
set `CrashControl` to minidump, reboot, and wait for the next BSOD to capture it.

## Fast path — the bundled script
`scripts/Get-BsodCulprit.ps1` (installed next to this skill) automates steps 1–4:
locate dump → symbols → `!analyze -v` → parse culprit → verdict + prioritized leads.
```powershell
# elevated PowerShell (auto-locates the newest dump under C:\Windows):
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude\skills\bsod-forensics\scripts\Get-BsodCulprit.ps1"
# or against a specific dump / saved analysis:
...\Get-BsodCulprit.ps1 -DumpPath C:\dumps\MEMORY.DMP
...\Get-BsodCulprit.ps1 -FromLog .\analysis.txt
```
Use the manual protocol below when the script cannot run or you need to go deeper.

## Manual protocol

### 1. Is there a dump, and in what format?
```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl').CrashDumpEnabled
```
Values: `0`=none · `1`=complete · `2`=kernel→`C:\Windows\MEMORY.DMP` (big)
· `3`=small minidump→`C:\Windows\Minidump\*.dmp` · `7`=automatic.
- If `0` or missing → set it to `3` (minidump) and **reboot** to capture the next one.
- Reading/copying `C:\Windows\*` **requires admin**. Copy the dump out before it gets overwritten.

### 2. Symbols (without them `!analyze` cannot name modules)
```
_NT_SYMBOL_PATH = srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
```
Create `C:\Symbols` and `setx _NT_SYMBOL_PATH ...` (persists). WinDbg downloads PDBs on demand.

### 3. WinDbg (`!analyze -v`)
- Install: `winget install Microsoft.WinDbg` (ships `WinDbgX.exe`, the modern UI).
- **Headless**: `cdb.exe` from the *Windows SDK Debugging Tools* (not part of modern WinDbg),
  or modern WinDbg: `WinDbgX.exe -z "<dump>" -c ".logopen <out.txt>; !analyze -v; .logclose; qd"`.
- It takes time: big dump + PDB download = several minutes. That is normal, not a hang.

### 4. Read the output (this IS the diagnosis)
| Field | What it gives |
|---|---|
| `BUGCHECK_CODE` + `P1..P4` | the `0xNN` (Arg2 is usually `rip`) |
| `MODULE_NAME` / `IMAGE_NAME` | the culprit **driver** (`dxgkrnl.sys`, `nvlddmkm.sys`…) |
| `SYMBOL_NAME` | the culprit **function** (`dxgkrnl!...::IsWsl2Guest+0`) |
| `FAILURE_BUCKET_ID` | Microsoft's bucket (the most web-searchable string) |
| `PROCESS_NAME` | originating process (`vmwp.exe`, `System`…) |
| `STACK_TEXT` | the stack that confirms the causal chain |
| `*** WARNING: Check Image - Checksum mismatch` | on-disk `.sys` does not match the build → corrupt/replaced → `sfc`/`DISM` |

### 5. Interpret the cause
- **Driver bug** → same bugcheck + same `rip` offset N times + named module. Fix: update/rollback
  the driver, or avoid the usage pattern that triggers it.
- **Flaky RAM** → VARIED BugCodes (`0x1a`, `0x50`, `0x4e`), different offsets every time, no
  consistent module. Confirm with MemTest86; check mixed DIMMs.
- **Thermal/CPU** → `0x101` (clock timeout), `0x124` (WHEA).
- **`.sys` checksum mismatch** → `sfc /scannow` + `DISM /Online /Cleanup-Image /RestoreHealth`.

## Output — present it like this
```
BSOD FORENSICS — <machine>
CULPRIT:  <module.sys> · function <SymbolName> · process <ProcessName>
   BugCheck 0xNN (args) · same offset N times = reproducible driver bug (not hardware)
   Stack:   <key chain, 3-5 frames>
   Cause:   <driver / RAM / thermal / corrupt binary>
Levers (prioritized, NOT executed): 1.… 2.…
```

## Red flags — STOP, you are diagnosing blind
- "It's RAM/hardware/PSU" without having opened the dump.
- You stopped at "a `0x3b` means…" as if the code were the diagnosis.
- You ran `!analyze` without `_NT_SYMBOL_PATH` → empty module names.
- You ruled out RAM **without** a named software module in the dump.
- "The dump is 4GB, I can't analyze that" → WinDbg loads it (slowly). Size is not an excuse.

## Rationalizations
| Excuse | Reality |
|---|---|
| "`0x3b` / `0x1a` is always RAM" | False. The code does not give the cause; the module in the dump does. |
| "It's hardware, let's swap the RAM" | Dump first. If it lands in `dxgkrnl`/`nvlddmkm`/a driver, it is not RAM. |
| "Event 1001 already gives the bugcheck" | It gives the code, not the culprit. The module lives in the dump. |
| "There is no dump" → "can't be done" | Set `CrashControl` to minidump + reboot + capture the next one. |

## Real-world example (Dell Precision Tower 3420, 2026-07)
3 BSODs in 3 days, all `0x3b (0xc0000005, 0xfffff8??_????6674, …)` — **same `…6674` offset**
all 3 times. `!analyze -v`:
- `MODULE_NAME: dxgkrnl` · `IMAGE_NAME: dxgkrnl.sys` · `PROCESS_NAME: vmwp.exe`
- `SYMBOL_NAME: dxgkrnl!DXGVIRTUALMACHINE::IsWsl2Guest+0`
- `FAILURE_BUCKET_ID: AV_dxgkrnl!DXGVIRTUALMACHINE::IsWsl2Guest`
- Stack: `vpcivsp!VirtualDeviceRemove` → `dxgkrnl!...ReadVirtualFunctionConfig` → `IsWsl2Guest`
  with `rcx=0` (null deref: `mov al,[rcx+164h]` reads invalid `[0x164]`).

→ **Null-deref in the WSL2 GPU-PV cleanup path** (Hyper-V removing the virtual GPU while the
VM shuts down). **Not hardware.** Without the dump, the mixed RAM sticks (a confound) would have
taken the blame. Levers: outdated 2022 GPU drivers + `wsl --shutdown` before powering off
(palliative). Full walkthrough: `case-studies/dxgkrnl-iswsl2guest/` in this repo.
