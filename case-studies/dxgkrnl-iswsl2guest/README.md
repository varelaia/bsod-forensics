# Case study: `dxgkrnl!DXGVIRTUALMACHINE::IsWsl2Guest` — the BSOD that looked like bad RAM

**Machine:** Dell Precision Tower 3420, Windows 10 build 19041, mixed RAM DIMMs,
NVIDIA Quadro K1200 (driver from 2022), heavy WSL2 user.
**Symptom:** 3 blue screens in 3 days, always near shutdown time. The obvious
(wrong) suspect: the mixed RAM sticks.

## What the Event Viewer said

Only this — three times:

```
BugCheck 0x3b (0xc0000005, 0xfffff80656786674, ..., 0)
SYSTEM_SERVICE_EXCEPTION
```

A `0x3b` is exactly the kind of code that gets waved away as "probably RAM".
Parts would have been swapped. The crashes would have continued.

## What the dump said (in minutes)

Running `!analyze -v` over the kernel dump — this is the raw, unedited output in
[`analysis.txt`](analysis.txt) — named the exact culprit:

```
MODULE_NAME:        dxgkrnl
IMAGE_NAME:         dxgkrnl.sys
PROCESS_NAME:       vmwp.exe
SYMBOL_NAME:        dxgkrnl!DXGVIRTUALMACHINE::IsWsl2Guest+0
FAILURE_BUCKET_ID:  AV_dxgkrnl!DXGVIRTUALMACHINE::IsWsl2Guest
```

The faulting instruction:

```
dxgkrnl!DXGVIRTUALMACHINE::IsWsl2Guest:
mov  al, byte ptr [rcx+164h]     ; rcx = 0  ->  null-pointer dereference
```

And the stack tells the story top to bottom: Hyper-V's virtual PCI provider
(`vpcivsp!VirtualDeviceRemove` → `VspEvtFileClose`) was **removing the
paravirtualized GPU (GPU-PV) of a closing VM** — the WSL2 utility VM, hence
`vmwp.exe` — and `dxgkrnl` dereferenced a null VM object in the cleanup path.

## The clincher: same offset, three times

All three crashes hit `rip` addresses ending in the **same low bits** (`…6674`) —
only the ASLR base differed between boots. Same instruction, three boots in a row:

- **Reproducible software bug** (a specific instruction in a specific function).
- Flaky RAM produces *varied* bugcheck codes at *varied* addresses — the opposite fingerprint.

That single observation is what rules hardware out with evidence instead of vibes.

## Verdict and levers

**Cause:** null-deref in the WSL2 GPU-PV cleanup path when the machine shuts down
with WSL2 still running. Contributing factors: 4-year-old GPU drivers (2022) and an
older Win10 build where GPU-PV was less mature. WinDbg also flagged a
`Checksum mismatch` on `dxgkrnl.sys` (possible corrupt/replaced binary).

Prioritized fixes:

1. **Palliative that stops the bleeding today:** `wsl --shutdown` before powering
   off/rebooting (avoids the dirty GPU-PV cleanup).
2. Update the GPU drivers (NVIDIA + iGPU).
3. `sfc /scannow` + `DISM /Online /Cleanup-Image /RestoreHealth` (checksum mismatch).
4. Windows Update / consider the newer Windows build.

## Why this case exists in the repo

It is the proof-point of the whole tool: a crash that pattern-matched to "bad RAM"
was actually a named, reproducible driver bug — and the dump said so in minutes.
**N = 1**: we present it as a demo of the method, not as a statistic.

Reproduce it against this very log without any dump or debugger:

```powershell
.\scripts\Get-BsodCulprit.ps1 -FromLog case-studies\dxgkrnl-iswsl2guest\analysis.txt
```
