# STweak 🚀

A lightweight, open-source Windows App Installer & System Tweak Tool inspired by Chris Titus Tech's WinUtil.

---

## ✨ Features

- **App Installer:** Easily install your favorite applications categorized by utility (Browsers, Developer Tools, Utilities, Media, etc.) via `winget`.
- **Safe & Reversible Tweaks:** Apply commonly-recommended and safe system optimizations (such as telemetry reduction, dark mode, file extensions) that can be easily reverted.
- **Full Uninstaller (Deep Clean):** Select one or more installed programs and remove them completely along with their leftover files and folders.
- **Action Log & Undo:** Tracks installed apps and applied tweaks in a local log file, allowing you to undo changes cleanly.
- **Privacy Focused:** Completely standalone with **no remote-control or remote-screen features** included.

---

## 💻 Manual Installation & Use

1. Download or clone this repository.
2. Right-click the launcher script (`launcher.bat`) and select **Run as Administrator**.
3. Use the tabs in the graphical interface to install apps, apply tweaks, or clean your system.

---

## 🛠️ Quick Start

Run the following command in PowerShell as an Administrator:

```powershell
irm https://raw.githubusercontent.com/MR-X905-dev/STweak/main/STweak.ps1 | iex
```


## 🧪 Run the Development Version

Want to try the latest development features? Run PowerShell as Administrator and execute:

```powershell
irm https://raw.githubusercontent.com/MR-X905-dev/STweak/refs/heads/dev/dev-STweak.ps1 | iex
```

> ⚠️ **Warning:** The development version may contain bugs or unfinished features. Review the script before running it.


