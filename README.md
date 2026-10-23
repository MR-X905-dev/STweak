# STweak 🚀

**A single-file PowerShell toolkit for Windows: apps, reversible tweaks, deep uninstall, cleanup and security in one dashboard.**

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white) ![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?logo=windows&logoColor=white) ![License](https://img.shields.io/badge/license-MIT-green)

One `.ps1` file with a WPF interface. Changes are backed up first, deletions go to quarantine, and no telemetry is collected.

## What's inside

| Page | What it does |
|---|---|
| 🏠 **Home** | Health check, live CPU/RAM/disk graphs, quick actions |
| 📦 **App Manager** | 142 apps in 10 categories via `winget`, plus upgrade scanning |
| 🎛️ **System Tweaks** | 59 reversible tweaks in 9 categories, with 4 presets |
| 🧨 **Deep Uninstall** | Remove a program, then its leftover folders, registry keys, services, tasks, shortcuts and Run entries |
| 🧹 **Smart Cleaner** | Measure and clear 9 junk locations (temp, update and shader caches, Recycle Bin) |
| 🧱 **Bloatware** | Remove built-in Store (AppX) packages, optionally for all users |
| 🛡️ **Security** | Defender, firewall, UAC and Secure Boot report, plus signature update and scans |
| ↩️ **Safe Restore** | Action history with one-click undo |
| 🗄️ **Quarantine** | Restore or purge deleted leftovers |
| 📝 **Activity Log** | In-app log viewer and data-folder shortcuts |

## Requirements

Windows 10/11 (x64) · PowerShell 5.1+ · Administrator · `winget` for the App Manager.

## Quick start

Run in an **elevated** PowerShell:

```powershell
irm https://raw.githubusercontent.com/MR-X905-dev/STweak/main/STweak.ps1 | iex
```

Or clone the repo and run `launcher.bat` (self-elevates). Manual: `powershell.exe -ExecutionPolicy Bypass -File .\STweak.ps1`

Dev build (may be unstable): `.../refs/heads/main/dev/dev-STweak.ps1`

## Presets

**Safe Starter** (low-risk baseline) · **Privacy Max** (telemetry and tracking off) · **Performance** (throttling, Game DVR, visual effects) · **Developer** (hidden files, long paths, dark mode, SMB1 off).

## Safety

Registry keys are exported to `.reg` and scheduled tasks to XML before writing. Deleted items move to `%ProgramData%\STweak\Quarantine` (Recycle Bin fallback) with a manifest and can be restored. Destructive actions ask for confirmation, and applied tweaks revert individually or all at once.

## Troubleshooting

- `running scripts is disabled` → use `launcher.bat` or `-ExecutionPolicy Bypass`
- `must run as Administrator` with `irm | iex` → start an elevated shell first
- Installs fail → check `winget --version`, then `winget source update`
- Self-test: add `-ValidateOnly` → `Tweaks: 59   Apps: 142   Presets: 4`

**MIT License** — see [LICENSE](LICENSE). Use only on machines you own or administer.
