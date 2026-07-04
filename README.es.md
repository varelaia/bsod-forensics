# bsod-forensics

**Encuentra el driver exacto detrás de un pantallazo azul de Windows — en minutos, no días.**

[English](README.md)

Un BSOD deja un código de bugcheck (`0x3b`, `0x1a`, …) en el Visor de Eventos, y ahí se
detienen la mayoría de los diagnósticos — casi siempre en *"seguro es la RAM"*. Pero el
código no es el diagnóstico. **El driver y la función culpables viven dentro del crash
dump**, y el `!analyze -v` de WinDbg los nombra explícitamente. Este repo automatiza ese flujo:

- un **script de PowerShell** (`Get-BsodCulprit.ps1`) que localiza el dump, corre el análisis
  e imprime culpable + evidencia + palancas priorizadas — sin saber de debugging;
- una **skill de [Claude Code](https://claude.com/claude-code)** que le enseña al agente el
  método forense completo (cuándo sospechar driver vs. RAM vs. térmico, los red flags, las trampas);
- un **[caso de estudio real](case-studies/dxgkrnl-iswsl2guest/)** donde un crash que parecía
  RAM defectuosa resultó ser un bug de driver, nombrado y reproducible.

## Quick start

Desde PowerShell (no requiere admin para instalar):

```powershell
irm https://raw.githubusercontent.com/varelaia/bsod-forensics/main/install.ps1 | iex
```

Qué hace (idempotente — seguro re-correrlo):

1. Planta la skill `bsod-forensics` en `%USERPROFILE%\.claude\skills\` (para usuarios de Claude Code).
2. Instala `Get-BsodCulprit.ps1` dentro de la carpeta de la skill (funciona standalone, sin IA).
3. Instala **WinDbg** vía `winget` — solo si no hay debugger presente. Sáltalo con `BSOD_NO_WINDBG=1`.
4. Setea `_NT_SYMBOL_PATH` (variable de usuario) — solo si no existe ya. Sáltalo con `BSOD_NO_SYMBOLPATH=1`.

O clona y corre el mismo installer local:

```powershell
git clone https://github.com/varelaia/bsod-forensics
cd bsod-forensics
.\install.ps1
```

## Uso

### A) Script standalone (sin IA)

Desde un PowerShell **elevado** (necesario para leer dumps bajo `C:\Windows`):

```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude\skills\bsod-forensics\scripts\Get-BsodCulprit.ps1"
```

O apúntalo a un dump que copiaste fuera (sin admin), o a un log de análisis guardado:

```powershell
Get-BsodCulprit.ps1 -DumpPath C:\dumps\MEMORY.DMP
Get-BsodCulprit.ps1 -FromLog .\analysis.txt      # offline, sin debugger
```

Output real (del caso de estudio de este repo):

```
=== BSOD FORENSICS ============================================
  BugCheck  : 0x3b SYSTEM_SERVICE_EXCEPTION
  CULPRIT   : dxgkrnl.sys
  Function  : dxgkrnl!DXGVIRTUALMACHINE::IsWsl2Guest+0
  Bucket    : AV_dxgkrnl!DXGVIRTUALMACHINE::IsWsl2Guest   <- search this string online
  Process   : vmwp.exe
  Verdict   : Named software module -> driver/component bug is the working
              hypothesis, NOT random hardware.
  ...
===============================================================
```

### B) Claude Code (modo agente)

Con la skill instalada, dile a Claude Code en la máquina afectada:

> "mi PC se puso azul, averigua por qué" / "analiza el BSOD"

La skill conduce el flujo completo — política de dumps, correr el script, leer la
evidencia — y aplica la regla de hierro del método: **no se afirma causa sin abrir el dump**.

## El caso demo: `dxgkrnl!IsWsl2Guest`

Una workstation Dell se puso azul 3 veces en 3 días con `0x3b SYSTEM_SERVICE_EXCEPTION` —
con RAM mezclada, "RAM defectuosa" era el sospechoso obvio. El dump nombró al culpable real
en minutos: un **null-pointer dereference en el cleanup de GPU-PV de WSL2** (`dxgkrnl.sys`),
disparado cada vez que el equipo se apagaba con WSL2 corriendo. Mismo offset de instrucción
las 3 veces = bug de driver reproducible, **no** hardware. La RAM se habría cambiado en vano.

Walkthrough completo con el output crudo de WinDbg: [case-studies/dxgkrnl-iswsl2guest/](case-studies/dxgkrnl-iswsl2guest/)

## Requisitos

- Windows 10/11, Windows PowerShell 5.1+ (preinstalado).
- `winget` (preinstalado en Windows actual) si hay que instalar WinDbg.
- Internet en el primer análisis (descarga de símbolos de Microsoft).
- Shell elevado **solo** para leer dumps bajo `C:\Windows` (modo auto-localizar).

## Limitaciones honestas

- **Un caso demo (N=1).** El método es forense estándar de WinDbg; nuestra evidencia de que
  le gana al diagnóstico a ciegas es un caso documentado a fondo, no una estadística.
- **Sin dump no hay forense.** Un congelamiento duro con `CrashDumpEnabled=0` no deja nada
  que analizar; el script te dice cómo habilitar minidumps para el *próximo* crash.
- **WinDbgX abre una ventana** durante el análisis (se cierra sola). El análisis 100% headless
  requiere `cdb.exe` del Windows SDK, que el script prefiere cuando está presente.
- Dumps grandes + primera descarga de símbolos toman varios minutos. Es normal.
- El veredicto es una **hipótesis de trabajo priorizada con evidencia**, no un oráculo.

## Rollback

```powershell
Remove-Item -Recurse "$env:USERPROFILE\.claude\skills\bsod-forensics"
# opcional: quitar el symbol path si lo seteo el installer
[Environment]::SetEnvironmentVariable('_NT_SYMBOL_PATH', $null, 'User')
# opcional: winget uninstall Microsoft.WinDbg
```

## Roadmap

- **v1.0** — `bsod-forensics`: identificación del culpable del BSOD + caso WSL2 GPU-PV. *(este release)*
- **v1.1** — `host-sentinel`: captura continua de evidencia (colector SQLite) para equipos
  que fallan intermitente, para que ningún crash quede sin registro.
- **v1.2** — más clases de falla: crashes de apps (Event 1000/1002), patrones WebView2/Electron.
- **v2.0** — relanzamiento como la suite **`windows-diagnostics`**: captura + forense, una instalación.

## Licencia

[MIT](LICENSE)
