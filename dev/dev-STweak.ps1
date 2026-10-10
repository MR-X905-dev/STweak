#Requires -RunAsAdministrator
<#
    STwaek - Windows App Installer, System Tweaks & Full Uninstaller
    Inspired by Chris Titus Tech's WinUtil (https://christitus.com/win)

    Design notes (read this if you're auditing the code):
    - Every tweak snapshots its OWN previous registry/service state before
      applying anything. "Undo" restores that exact saved state - it does
      NOT assume a hardcoded default. If a value didn't exist before, undo
      removes it; if it existed, undo restores the exact previous value.
    - Tweak names avoid promising specific performance gains (FPS, speed).
      They're described as commonly recommended, with results varying by
      machine - because that is what's actually true.
    - The "deep uninstall" leftover scan only proposes (a) the program's own
      registered install folder and (b) an AppData/ProgramData folder whose
      name EXACTLY matches the program. Every candidate passes one gatekeeper
      (Test-SafeLeftoverPath): allowed roots only, protected names, personal
      data folders, symlinks/junctions, other programs' folders and running
      processes are all refused - and it is re-checked right before removal.
      Items are unticked by default, need typing DELETE, and are moved to a
      quarantine folder unless permanent deletion is explicitly ticked.
    - The Security tab does not implement a custom virus scanner. It calls
      Windows Defender's own official cmdlets (Start-MpScan, Get-MpThreat,
      Remove-MpThreat) so detection/removal is backed by Microsoft's real
      antivirus engine, not a hand-rolled heuristic that could be wrong in
      either direction.
    - No remote-control / remote-screen feature is included in this tool.
    - DRY RUN mode (checkbox at the bottom, ON by default): every action
      button only READS the system and prints what it WOULD do to the Log
      tab. Nothing is installed, uninstalled, changed, deleted, scanned or
      written to the action log while Dry Run is checked.
#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# ============================================================================
# Paths / action log "
# ============================================================================
$LogDir  = Join-Path $env:ProgramData "STwaek"
$LogFile = Join-Path $LogDir "actions.json"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$QuarantineDir = Join-Path $LogDir "Quarantine"

function Write-LogSafe($Text) {
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) { Write-Log $Text } else { Write-Host $Text }
}

function New-EmptyActionLog {
    [PSCustomObject]@{ schemaVersion = 2; installedApps = @(); appliedTweaks = @() }
}

# Reads and VALIDATES the action log. A damaged file is never silently
# discarded: a copy is kept as *.corrupt-<time>, and the last good backup
# (.bak, written by every save) is tried before falling back to an empty log.
function Get-ActionLog {
    foreach ($candidate in @($LogFile, "$LogFile.bak")) {
        if (-not (Test-Path -LiteralPath $candidate)) { continue }
        try {
            $raw = Get-Content -LiteralPath $candidate -Raw -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($raw)) { throw "file is empty" }
            $obj = $raw | ConvertFrom-Json -ErrorAction Stop
            $names = @($obj.PSObject.Properties.Name)
            if (($names -notcontains 'installedApps') -or ($names -notcontains 'appliedTweaks')) { throw "unexpected structure" }
            $obj.installedApps  = @($obj.installedApps  | Where-Object { $_ })
            $obj.appliedTweaks = @($obj.appliedTweaks | Where-Object { $_ })
            if ($candidate -ne $LogFile) { Write-LogSafe "WARNING: the main action log was damaged; recovered from the backup copy." }
            return $obj
        } catch {
            $aside = "$candidate.corrupt-" + (Get-Date -Format "yyyyMMdd-HHmmss")
            try { Copy-Item -LiteralPath $candidate -Destination $aside -ErrorAction Stop } catch { }
            Write-LogSafe "WARNING: could not read $candidate ($($_.Exception.Message)). A copy was kept at $aside"
        }
    }
    return (New-EmptyActionLog)
}

# Atomic save: write to a temp file, prove it parses back, then swap it in
# (keeping the previous version as .bak). A crash mid-write can no longer
# leave a half-written action log.
function Save-ActionLog($log) {
    $log | Add-Member -NotePropertyName schemaVersion -NotePropertyValue 2 -Force
    $tmp = "$LogFile.tmp"
    $json = $log | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8 -ErrorAction Stop
    $null = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json -ErrorAction Stop
    if (Test-Path -LiteralPath $LogFile) {
        [System.IO.File]::Replace($tmp, $LogFile, "$LogFile.bak")
    } else {
        Move-Item -LiteralPath $tmp -Destination $LogFile -Force
    }
}

if (-not (Test-Path -LiteralPath $LogFile)) { Save-ActionLog (New-EmptyActionLog) }

# True while the "Dry Run" checkbox is checked. $ChkDryRun is created later
# when the window is built; this is only evaluated at click time.
function Test-DryRun { return ($null -ne $ChkDryRun -and $ChkDryRun.IsChecked -eq $true) }

# Converts a PSCustomObject (as produced by ConvertFrom-Json) back into a
# plain Hashtable so tweak Restore scriptblocks can index it with ["key"].
function ConvertTo-HashtableDeep($obj) {
    if ($null -eq $obj) { return @{} }
    if ($obj -is [System.Collections.IDictionary]) { return $obj }
    $h = @{}
    foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = $p.Value }
    return $h
}

# Human-readable lines describing what Undo WOULD restore from a saved state.
function Format-SavedState($State) {
    $h = ConvertTo-HashtableDeep $State
    foreach ($k in $h.Keys) {
        $v = $h[$k]
        if ($v -is [System.Management.Automation.PSCustomObject] -or $v -is [System.Collections.IDictionary]) {
            $inner = ConvertTo-HashtableDeep $v
            if ($inner.ContainsKey('Exists')) {
                if ($inner.Exists) { "$k -> restore to '$($inner.Value)' (type $($inner.Kind))" }
                else               { "$k -> remove (did not exist before)" }
                continue
            }
        }
        "$k = $v"
    }
}

function Add-InstalledApp($wingetId, $displayName) {
    $log = Get-ActionLog
    $list = @($log.installedApps)
    if (-not ($list | Where-Object { $_.id -eq $wingetId })) {
        $list += [PSCustomObject]@{ id = $wingetId; name = $displayName; date = (Get-Date).ToString("s") }
    }
    $log.installedApps = $list
    Save-ActionLog $log
}

function Add-AppliedTweak($tweakKey, $displayName, $state) {
    $log = Get-ActionLog
    $list = @($log.appliedTweaks)
    $existing = $list | Where-Object { $_.key -eq $tweakKey }
    if ($existing) {
        # Already applied before: keep the ORIGINAL saved baseline state
        # (that's the real pre-tweak value); only refresh the date.
        foreach ($item in $list) { if ($item.key -eq $tweakKey) { $item.date = (Get-Date).ToString("s") } }
    } else {
        $list += [PSCustomObject]@{ key = $tweakKey; name = $displayName; date = (Get-Date).ToString("s"); state = $state }
    }
    $log.appliedTweaks = $list
    Save-ActionLog $log
}

function Merge-AppliedTweakExtraState($tweakKey, $extra) {
    if (-not $extra) { return }
    $log = Get-ActionLog
    foreach ($item in $log.appliedTweaks) {
        if ($item.key -eq $tweakKey) {
            $merged = ConvertTo-HashtableDeep $item.state
            foreach ($k in $extra.Keys) { $merged[$k] = $extra[$k] }
            $item.state = $merged
        }
    }
    Save-ActionLog $log
}

function Remove-AppliedTweakEntry($tweakKey) {
    $log = Get-ActionLog
    $log.appliedTweaks = @($log.appliedTweaks | Where-Object { $_.key -ne $tweakKey })
    Save-ActionLog $log
}

function Remove-InstalledAppEntry($wingetId) {
    $log = Get-ActionLog
    $log.installedApps = @($log.installedApps | Where-Object { $_.id -ne $wingetId })
    Save-ActionLog $log
}

# ============================================================================
# App catalog (winget IDs), grouped by category
# ============================================================================
function App($Name, $Id, $Cat) { [PSCustomObject]@{ Name = $Name; Id = $Id; Cat = $Cat } }

$AppCatalog = @(
    # Browsers
    (App "Google Chrome"        "Google.Chrome"               "Browsers")
    (App "Mozilla Firefox"      "Mozilla.Firefox"              "Browsers")
    (App "Brave Browser"        "Brave.Brave"                  "Browsers")
    (App "Opera"                "Opera.Opera"                  "Browsers")
    (App "Opera GX"             "Opera.OperaGX"                "Browsers")
    (App "Vivaldi"              "VivaldiTechnologies.Vivaldi"  "Browsers")
    (App "Tor Browser"          "TorProject.TorBrowser"        "Browsers")

    # Developer Tools
    (App "Visual Studio Code"   "Microsoft.VisualStudioCode"   "Developer Tools")
    (App "Visual Studio Community" "Microsoft.VisualStudio.2022.Community" "Developer Tools")
    (App "Git"                  "Git.Git"                      "Developer Tools")
    (App "GitHub Desktop"       "GitHub.GitHubDesktop"         "Developer Tools")
    (App "GitHub CLI"           "GitHub.cli"                   "Developer Tools")
    (App "Node.js LTS"          "OpenJS.NodeJS.LTS"            "Developer Tools")
    (App "Python 3"             "Python.Python.3.12"           "Developer Tools")
    (App "Eclipse Temurin JDK"  "EclipseAdoptium.Temurin.21.JDK" "Developer Tools")
    (App "Windows Terminal"     "Microsoft.WindowsTerminal"    "Developer Tools")
    (App "PowerShell 7"         "Microsoft.PowerShell"         "Developer Tools")
    (App "Docker Desktop"       "Docker.DockerDesktop"         "Developer Tools")
    (App "Postman"              "Postman.Postman"              "Developer Tools")
    (App "Insomnia"             "Insomnia.Insomnia"            "Developer Tools")
    (App "JetBrains Toolbox"    "JetBrains.Toolbox"            "Developer Tools")
    (App "DBeaver"              "dbeaver.dbeaver"              "Developer Tools")
    (App "MongoDB Compass"      "MongoDB.Compass.Full"         "Developer Tools")
    (App "Sublime Text"         "SublimeHQ.SublimeText.4"      "Developer Tools")
    (App "CMake"                "Kitware.CMake"                "Developer Tools")

    # System Utilities
    (App "7-Zip"                "7zip.7zip"                    "System Utilities")
    (App "WinRAR"               "RARLab.WinRAR"                "System Utilities")
    (App "PowerToys"            "Microsoft.PowerToys"          "System Utilities")
    (App "Everything (search)"  "voidtools.Everything"         "System Utilities")
    (App "TreeSize Free"        "JAMSoftware.TreeSize.Free"    "System Utilities")
    (App "Revo Uninstaller"     "RevoUninstaller.RevoUninstaller" "System Utilities")
    (App "Rufus"                "Rufus.Rufus"                  "System Utilities")
    (App "balenaEtcher"         "Balena.Etcher"                "System Utilities")
    (App "Notepad++"            "Notepad++.Notepad++"          "System Utilities")

    # Media & Creative
    (App "VLC Media Player"     "VideoLAN.VLC"                 "Media & Creative")
    (App "OBS Studio"           "OBSProject.OBSStudio"         "Media & Creative")
    (App "HandBrake"            "HandBrake.HandBrake"          "Media & Creative")
    (App "Spotify"              "Spotify.Spotify"              "Media & Creative")
    (App "Audacity"             "Audacity.Audacity"            "Media & Creative")
    (App "IrfanView"            "IrfanSkiljan.IrfanView"       "Media & Creative")
    (App "GIMP"                 "GIMP.GIMP"                    "Media & Creative")
    (App "Inkscape"             "Inkscape.Inkscape"            "Media & Creative")
    (App "Blender"              "BlenderFoundation.Blender"    "Media & Creative")
    (App "Krita"                "KDE.Krita"                    "Media & Creative")
    (App "Paint.NET"            "dotPDNLLC.paintdotnet"        "Media & Creative")

    # Communication
    (App "Discord"              "Discord.Discord"              "Communication")
    (App "Telegram"             "Telegram.TelegramDesktop"     "Communication")
    (App "Zoom"                 "Zoom.Zoom"                    "Communication")
    (App "Slack"                "SlackTechnologies.Slack"      "Communication")
    (App "Microsoft Teams"      "Microsoft.Teams"              "Communication")
    (App "WhatsApp"             "WhatsApp.WhatsApp"            "Communication")

    # Productivity
    (App "LibreOffice"          "TheDocumentFoundation.LibreOffice" "Productivity")
    (App "Adobe Acrobat Reader" "Adobe.Acrobat.Reader.64-bit"  "Productivity")
    (App "Notion"               "Notion.Notion"                "Productivity")
    (App "Obsidian"             "Obsidian.Obsidian"            "Productivity")
    (App "Sumatra PDF"          "SumatraPDF.SumatraPDF"        "Productivity")
    (App "Joplin"               "Joplin.Joplin"                "Productivity")

    # Security & Privacy
    (App "Malwarebytes"         "Malwarebytes.Malwarebytes"    "Security & Privacy")
    (App "Bitwarden"            "Bitwarden.Bitwarden"          "Security & Privacy")
    (App "KeePass"              "DominikReichl.KeePass"        "Security & Privacy")

    # Gaming
    (App "Steam"                "Valve.Steam"                  "Gaming")
    (App "Epic Games Launcher"  "EpicGames.EpicGamesLauncher"  "Gaming")
    (App "GOG Galaxy"           "GOG.Galaxy"                   "Gaming")

    # Cloud Storage
    (App "Google Drive"         "Google.GoogleDrive"           "Cloud Storage")
    (App "Dropbox"              "Dropbox.Dropbox"              "Cloud Storage")

    # Networking
    (App "Wireshark"            "WiresharkFoundation.Wireshark" "Networking")
    (App "PuTTY"                "PuTTY.PuTTY"                  "Networking")
    (App "WinSCP"                "WinSCP.WinSCP"                "Networking")

    # Virtualization
    (App "VirtualBox"           "Oracle.VirtualBox"            "Virtualization")
)

# ============================================================================
# Tweak engine - every tweak exposes GetState / Plan / Apply / Restore so
# "Undo" restores the EXACT previous value instead of a guessed default, and
# Dry Run can describe the change (Plan) without performing it (Apply).
# ============================================================================
# Returns a rich snapshot: whether the value existed, its value, AND its
# original RegistryValueKind - so Restore can recreate it with the EXACT
# original type instead of whatever type the tweak happens to use.
function Get-RegValueOrNull($Path, $Name) {
    if (Test-Path $Path) {
        try {
            $key = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($key.GetValueNames() -contains $Name) {
                $val  = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $kind = $key.GetValueKind($Name).ToString()
                return @{ Exists = $true; Value = $val; Kind = $kind }
            }
        } catch { }
    }
    return @{ Exists = $false; Value = $null; Kind = $null }
}

# $PrevState is the rich snapshot from Get-RegValueOrNull (possibly round-tripped
# through JSON, so it may arrive as a PSCustomObject - hence the conversion).
function Set-RegValueOrRemove($Path, $Name, $PrevState, $FallbackType) {
    $PrevState = ConvertTo-HashtableDeep $PrevState
    if (-not $PrevState.Exists) {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        return
    }
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    $type = if ($PrevState.Kind) { $PrevState.Kind } else { $FallbackType }
    Set-ItemProperty -Path $Path -Name $Name -Value $PrevState.Value -Type $type
}

# Builds a tweak whose state is a flat set of registry values. Each target:
# @{ Path=...; Name=...; Type=...; Value=<value to set when applied> }
function New-RegTweak($Key, $Name, [array]$Targets) {
    [PSCustomObject]@{
        Key  = $Key
        Name = $Name
        GetState = {
            $state = @{}
            foreach ($t in $Targets) { $state["$($t.Path)|$($t.Name)"] = Get-RegValueOrNull -Path $t.Path -Name $t.Name }
            return $state
        }.GetNewClosure()
        # Dry Run: describes each registry change (current value -> new value).
        Plan = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            foreach ($t in $Targets) {
                $prev = ConvertTo-HashtableDeep $State["$($t.Path)|$($t.Name)"]
                $cur  = if ($prev.Exists) { "$($prev.Value)" } else { "<not set>" }
                "SET $($t.Path)\$($t.Name) ($($t.Type)): $cur -> $($t.Value)"
            }
        }.GetNewClosure()
        Apply = {
            foreach ($t in $Targets) {
                if (-not (Test-Path $t.Path)) { New-Item -Path $t.Path -Force | Out-Null }
                Set-ItemProperty -Path $t.Path -Name $t.Name -Value $t.Value -Type $t.Type
            }
            return $null
        }.GetNewClosure()
        Restore = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            foreach ($t in $Targets) {
                $prev = $State["$($t.Path)|$($t.Name)"]
                Set-RegValueOrRemove -Path $t.Path -Name $t.Name -PrevState $prev -FallbackType $t.Type
            }
        }.GetNewClosure()
    }
}

$TweakCatalog = @(
    (New-RegTweak "DisableTelemetry" "Disable Windows Telemetry" @(
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Type="DWord"; Value=0 }
    ))
    (New-RegTweak "DisableAdvertisingID" "Disable Advertising ID" @(
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name="Enabled"; Type="DWord"; Value=0 }
    ))
    (New-RegTweak "DisableActivityHistory" "Disable Activity History / Timeline" @(
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableActivityFeed"; Type="DWord"; Value=0 }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="PublishUserActivities"; Type="DWord"; Value=0 }
    ))
    (New-RegTweak "DisableLocationTracking" "Disable Location Tracking" @(
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name="DisableLocation"; Type="DWord"; Value=1 }
    ))
    (New-RegTweak "DisableCortanaWebSearch" "Disable Web Search in Start Menu" @(
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name="BingSearchEnabled"; Type="DWord"; Value=0 }
    ))
    (New-RegTweak "DisableGameBar" "Disable Xbox Game Bar / Game DVR" @(
        @{ Path="HKCU:\System\GameConfigStore"; Name="GameDVR_Enabled"; Type="DWord"; Value=0 }
    ))
    (New-RegTweak "DisableBackgroundApps" "Disable Background Running Apps" @(
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"; Name="GlobalUserDisabled"; Type="DWord"; Value=1 }
    ))
    (New-RegTweak "DisableFastStartup" "Disable Fast Startup" @(
        @{ Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"; Name="HiberbootEnabled"; Type="DWord"; Value=0 }
    ))
    (New-RegTweak "DisableStartupDelay" "Disable Startup App Delay (apps often start slightly faster at logon)" @(
        @{ Path="HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Serialize"; Name="StartupDelayInMSec"; Type="DWord"; Value=0 }
    ))
    (New-RegTweak "DisableWindowsUpdateAutoRestart" "Disable Windows Update Auto-Restart While Logged In" @(
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="NoAutoRebootWithLoggedOnUsers"; Type="DWord"; Value=1 }
    ))
    (New-RegTweak "ShowFileExtensions" "Show File Extensions in Explorer" @(
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="HideFileExt"; Type="DWord"; Value=0 }
    ))
    (New-RegTweak "ShowHiddenFiles" "Show Hidden Files" @(
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="Hidden"; Type="DWord"; Value=1 }
    ))
    (New-RegTweak "ShowThisPCOnDesktop" "Show 'This PC' Icon on Desktop" @(
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"; Name="{20D04FE0-3AEA-1069-A2D8-08002B30309D}"; Type="DWord"; Value=0 }
    ))
    (New-RegTweak "DarkMode" "Enable Dark Mode (Apps + System)" @(
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"; Name="AppsUseLightTheme"; Type="DWord"; Value=0 }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"; Name="SystemUsesLightTheme"; Type="DWord"; Value=0 }
    ))
    (New-RegTweak "AlignTaskbarLeft" "Align Taskbar Icons to the Left (Windows 11)" @(
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="TaskbarAl"; Type="DWord"; Value=0 }
    ))
    (New-RegTweak "DisableStickyKeysPrompt" "Disable Sticky Keys Shortcut Prompt" @(
        @{ Path="HKCU:\Control Panel\Accessibility\StickyKeys"; Name="Flags"; Type="String"; Value="58" }
    ))

    # ---- Custom (non-registry-only) tweaks: exact state capture per case ----
    [PSCustomObject]@{
        Key = "DisableSysMain"
        Name = "Disable SysMain / Superfetch (commonly suggested for SSDs; effect varies by system)"
        GetState = {
            $svc = Get-Service -Name SysMain -ErrorAction SilentlyContinue
            if ($svc) { @{ Found = $true; StartType = $svc.StartType.ToString(); Status = $svc.Status.ToString() } }
            else { @{ Found = $false } }
        }
        Plan = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            if ($State.Found) { "SERVICE SysMain: StartType=$($State.StartType), Status=$($State.Status) -> Stop service + StartType=Disabled" }
            else { "SERVICE SysMain not found on this system - nothing would change" }
        }
        Apply = { Stop-Service -Name SysMain -Force -ErrorAction SilentlyContinue; Set-Service -Name SysMain -StartupType Disabled -ErrorAction SilentlyContinue; return $null }
        Restore = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            if (-not $State.Found) { return }
            Set-Service -Name SysMain -StartupType $State.StartType -ErrorAction SilentlyContinue
            if ($State.Status -eq "Running") { Start-Service -Name SysMain -ErrorAction SilentlyContinue }
        }
    }
    [PSCustomObject]@{
        Key = "DisableHibernation"
        Name = "Disable Hibernation (frees the hiberfil.sys disk space; also removes hibernate/fast-startup options)"
        GetState = {
            # Don't assume "on" when the registry value is missing - ask Windows
            # directly whether hibernation is actually available right now.
            $a = (powercfg /a) -join "`n"
            $wasAvailable = $a -match "Hibernate"
            @{ WasAvailable = [bool]$wasAvailable }
        }
        Plan = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            "COMMAND powercfg /hibernate off (hibernation currently detected as available: $($State.WasAvailable))"
        }
        Apply = { powercfg /hibernate off; return $null }
        Restore = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            if ($State.WasAvailable) { powercfg /hibernate on } else { powercfg /hibernate off }
        }
    }
    [PSCustomObject]@{
        Key = "UltimatePerformancePlan"
        Name = "Switch to Ultimate Performance Power Plan (commonly suggested; does not guarantee higher FPS or speed)"
        GetState = {
            $active = powercfg -getactivescheme
            $guid = $null
            if ($active -match '([0-9a-fA-F-]{36})') { $guid = $Matches[1] }
            @{ PreviousGuid = $guid }
        }
        Plan = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            "POWER PLAN currently active: $($State.PreviousGuid)"
            "POWER PLAN would run: powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61, then activate the new plan"
        }
        Apply = {
            powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
            $createdGuid = $null
            $created = (powercfg -list | Select-String "Ultimate Performance")
            if ($created -and ($created.ToString() -match '([0-9a-fA-F-]{36})')) {
                $createdGuid = $Matches[1]
                powercfg -setactive $createdGuid
            }
            # Returned value is merged into this tweak's saved state so Restore
            # knows exactly which duplicated plan to clean up.
            return @{ CreatedGuid = $createdGuid }
        }
        Restore = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            if ($State.PreviousGuid) { powercfg -setactive $State.PreviousGuid }
            if ($State.CreatedGuid) { powercfg -delete $State.CreatedGuid 2>$null }
        }
    }
    [PSCustomObject]@{
        Key = "ClassicRightClickMenu"
        Name = "Restore Classic Right-Click Menu (Windows 11)"
        GetState = {
            $path = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
            $existed = Test-Path $path
            $prevDefault = $null
            if ($existed) {
                try { $prevDefault = (Get-Item -LiteralPath $path).GetValue("") } catch { }
            }
            @{ Existed = $existed; PrevDefaultValue = $prevDefault }
        }
        Plan = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            "REGISTRY key HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32 (already exists: $($State.Existed)) -> would be created/set with an empty (default) value"
        }
        Apply = {
            New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(default)" -Value "" -Type String
            return $null
        }
        Restore = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            if (-not $State.Existed) {
                Remove-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                $path = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
                $val = if ($null -ne $State.PrevDefaultValue) { $State.PrevDefaultValue } else { "" }
                if (Test-Path $path) { Set-ItemProperty -Path $path -Name "(default)" -Value $val -Type String }
            }
        }
    }
)

# ============================================================================
# Uninstall tab: enumerate installed programs, run their real uninstaller,
# then SAFELY propose leftover files/folders for review (never auto-delete).
# ============================================================================
function Get-InstalledPrograms {
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $raw = foreach ($p in $uninstallPaths) { Get-ItemProperty -Path $p -ErrorAction SilentlyContinue }
    $raw |
        Where-Object { $_.DisplayName -and -not $_.SystemComponent -and ($_.UninstallString -or $_.QuietUninstallString) } |
        Group-Object DisplayName |
        ForEach-Object {
            $e = $_.Group[0]
            [PSCustomObject]@{
                DisplayName          = $e.DisplayName
                Publisher            = $e.Publisher
                DisplayVersion       = $e.DisplayVersion
                InstallLocation      = $e.InstallLocation
                UninstallString      = $e.UninstallString
                QuietUninstallString = $e.QuietUninstallString
            }
        } | Sort-Object DisplayName
}

# Folder names that are NEVER offered for removal: checked against the candidate
# itself AND every folder below its allowed root.
$ProtectedFolderNames = @(
    "Documents","Desktop","Pictures","Videos","Music","Downloads",
    "OneDrive","Dropbox","Backup","Backups","Important","Personal","Projects",
    "Users","Public","Contacts","Favorites","Links","Saved Games","Camera Roll",
    "Work","Source","Sources","Repos","Repositories",
    "Windows","System32","SysWOW64","WindowsApps","Common Files","Microsoft","Programs","Packages","Temp"
)

function Get-NormalizedPath([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    try { return [System.IO.Path]::GetFullPath($p.Trim().Trim('"')).TrimEnd('\') } catch { return $null }
}

function Test-PathUnder([string]$Child, [string]$Parent) {
    if (-not $Child -or -not $Parent) { return $false }
    return $Child.StartsWith($Parent.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

# The ONLY places a leftover may live. Anything outside is refused.
function Get-LeftoverAllowedRoots {
    $r = @($env:ProgramData, $env:LOCALAPPDATA, $env:APPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)})
    if ($env:LOCALAPPDATA) { $r += (Join-Path $env:LOCALAPPDATA "Programs") }
    @($r | ForEach-Object { Get-NormalizedPath $_ } | Where-Object { $_ } | Select-Object -Unique)
}

function Get-UserDataFolders {
    $list = @()
    foreach ($sf in 'MyDocuments','Desktop','MyPictures','MyMusic','MyVideos') { $list += [Environment]::GetFolderPath($sf) }
    if ($env:USERPROFILE) { $list += (Join-Path $env:USERPROFILE "Downloads") }
    $list += @($env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial)
    @($list | ForEach-Object { Get-NormalizedPath $_ } | Where-Object { $_ } | Select-Object -Unique)
}

# Single gatekeeper used BOTH when proposing a leftover and again immediately
# before touching it. Returns @{ Safe = $true/$false; Reason = ... }.
function Test-SafeLeftoverPath {
    param([string]$Path, [array]$OtherInstallLocations = @())

    $deny = { param($why) [PSCustomObject]@{ Safe = $false; Reason = $why } }

    $full = Get-NormalizedPath $Path
    if (-not $full) { return (& $deny "path could not be resolved") }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { return (& $deny "not an existing folder") }

    $pathRoot = [System.IO.Path]::GetPathRoot($full)
    if ($pathRoot -and ($pathRoot.TrimEnd('\') -ieq $full)) { return (& $deny "drive root") }

    $roots = @(Get-LeftoverAllowedRoots)
    if ($roots | Where-Object { $_ -ieq $full }) { return (& $deny "is itself a top-level system/app-data folder") }

    $root = $roots | Where-Object { Test-PathUnder $full $_ } | Sort-Object Length -Descending | Select-Object -First 1
    if (-not $root) { return (& $deny "outside the allowed locations (ProgramData, AppData, Local\Programs, Program Files)") }

    $relative = $full.Substring($root.Length).TrimStart('\')
    foreach ($seg in ($relative -split '\\')) {
        if ($ProtectedFolderNames -contains $seg) { return (& $deny "path contains the protected folder name '$seg'") }
    }

    foreach ($u in (Get-UserDataFolders)) {
        if ($full -ieq $u -or (Test-PathUnder $full $u) -or (Test-PathUnder $u $full)) {
            return (& $deny "overlaps a personal data folder ($u)")
        }
    }

    $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
    if (-not $item) { return (& $deny "could not be inspected") }
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { return (& $deny "is a symbolic link / junction") }

    $cursor = Split-Path $full -Parent
    while ($cursor -and (Test-PathUnder $cursor $root)) {
        $p = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if ($p -and ($p.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return (& $deny "a parent folder is a symbolic link / junction ($cursor)") }
        $cursor = Split-Path $cursor -Parent
    }

    $nested = Get-ChildItem -LiteralPath $full -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($nested) { return (& $deny "contains a symbolic link / junction ($($nested.FullName))") }

    foreach ($o in $OtherInstallLocations) {
        $on = Get-NormalizedPath $o
        if (-not $on) { continue }
        if ($on -ieq $full -or (Test-PathUnder $on $full) -or (Test-PathUnder $full $on)) {
            return (& $deny "overlaps the install folder of another installed program ($on)")
        }
    }

    $busy = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and (Test-PathUnder $_.Path $full) } | Select-Object -First 1
    if ($busy) { return (& $deny "process '$($busy.ProcessName)' is still running from this folder") }

    return [PSCustomObject]@{ Safe = $true; Reason = "" }
}

function Find-LeftoverPaths {
    param($App, [array]$OtherInstallLocations = @())

    $nameGuess = ($App.DisplayName -replace '[^\w\s]', '').Trim()
    # EXACT folder-name match only (with or without spaces). No prefix/suffix/
    # "contains" matching and no publisher matching - those are how a different
    # program's data gets flagged by mistake.
    $variants = @($nameGuess, ($nameGuess -replace '\s', '')) | Where-Object { $_ -and $_.Length -ge 4 } | Select-Object -Unique

    $candidates = @()

    # 1) The authoritative path: exactly what the registry says it installed to.
    $loc = if ($App.InstallLocation) { Get-NormalizedPath $App.InstallLocation } else { $null }
    if ($loc -and (Test-Path -LiteralPath $loc -PathType Container)) { $candidates += $loc }

    # 2) Per-user/app DATA folders, exact name only.
    if ($variants) {
        $dataRoots = @($env:ProgramData, $env:LOCALAPPDATA, $env:APPDATA, (Join-Path $env:LOCALAPPDATA "Programs")) |
            Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
        foreach ($root in $dataRoots) {
            $candidates += Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $variants -contains $_.Name } |
                Select-Object -ExpandProperty FullName
        }
    }

    foreach ($path in ($candidates | Where-Object { $_ } | Select-Object -Unique)) {
        $check = Test-SafeLeftoverPath -Path $path -OtherInstallLocations $OtherInstallLocations
        if (-not $check.Safe) {
            Write-Log "Skipped (not safe to offer): $path - $($check.Reason)"
            continue
        }
        $files = Get-ChildItem -LiteralPath $path -Recurse -File -Force -ErrorAction SilentlyContinue
        $sizeMB = [math]::Round((($files | Measure-Object -Property Length -Sum).Sum / 1MB), 2)
        [PSCustomObject]@{
            Path      = $path
            SizeMB    = $sizeMB
            FileCount = @($files).Count
        }
    }
}

# Removes ONE leftover folder. Re-validates right before acting (the folder may
# have changed since it was listed). Default = move to a quarantine folder that
# can be restored by hand; permanent deletion only when explicitly requested.
function Remove-LeftoverSafely {
    param([string]$Path, [array]$OtherInstallLocations = @(), [bool]$Permanent = $false)

    $check = Test-SafeLeftoverPath -Path $Path -OtherInstallLocations $OtherInstallLocations
    if (-not $check.Safe) {
        Write-Log "REFUSED to touch $Path - $($check.Reason)"
        return $false
    }

    try {
        if ($Permanent) {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            Write-Log "Permanently deleted leftover: $Path"
        } else {
            $stamp    = Get-Date -Format "yyyyMMdd-HHmmss"
            $destRoot = Join-Path $QuarantineDir $stamp
            New-Item -ItemType Directory -Path $destRoot -Force | Out-Null
            $leaf = [System.IO.Path]::GetFileName($Path)
            $dest = Join-Path $destRoot ($leaf + "_" + [guid]::NewGuid().ToString("N").Substring(0, 8))
            Move-Item -LiteralPath $Path -Destination $dest -ErrorAction Stop

            $manifestFile = Join-Path $QuarantineDir "manifest.json"
            $entries = @()
            if (Test-Path -LiteralPath $manifestFile) {
                try { $entries = @(Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json) } catch { $entries = @() }
            }
            $entries += [PSCustomObject]@{ original = $Path; quarantined = $dest; date = (Get-Date).ToString("s") }
            ConvertTo-Json -InputObject @($entries) -Depth 4 | Set-Content -LiteralPath $manifestFile -Encoding UTF8
            Write-Log "Moved to quarantine: $Path  ->  $dest   (restore by moving it back; see $manifestFile)"
        }
        return $true
    } catch {
        Write-Log "FAILED to remove $Path : $($_.Exception.Message)"
        return $false
    }
}

# Runs an uninstall string from the registry under strict rules:
#  - commands with chaining/download/encoded-PowerShell patterns are REFUSED
#  - it must resolve to a real .exe file (no cmd /c fallback, ever)
#  - msiexec /I (modify/repair) is converted to /X (uninstall)
#  - an unsigned or invalidly signed executable needs explicit confirmation
#  - the real exit code decides success (0, 3010 and 1641 count as success)
# In Dry Run it performs the same analysis but NEVER executes anything.
function Invoke-UninstallCommand {
    param([string]$RawCommand)

    $result = [PSCustomObject]@{ Success = $false; ExitCode = $null; Message = "" }
    $dry = Test-DryRun
    if ([string]::IsNullOrWhiteSpace($RawCommand)) { $result.Message = "Empty uninstall command."; return $result }

    $unsafePatterns = @('&&', '\|\|', '&', '\|', ';\s*\S', 'https?://', '-enc\b', '-EncodedCommand', 'Invoke-Expression', '\biex\b', 'DownloadString', 'Invoke-WebRequest', '%COMSPEC%', '\bcmd(\.exe)?\s+/c\b', '\bpowershell(\.exe)?\b', '\bpwsh(\.exe)?\b')
    foreach ($pat in $unsafePatterns) {
        if ($RawCommand -match $pat) {
            $result.Message = "Refused: the registered uninstall command matches the unsafe pattern '$pat'. Remove this program manually from Windows Settings."
            if ($dry) { Write-Log "[DRY RUN] This command would be REFUSED (unsafe pattern '$pat')." }
            return $result
        }
    }

    $exeToken = $null; $argString = ""
    if ($RawCommand -match '^\s*"([^"]+)"\s*(.*)$') { $exeToken = $Matches[1]; $argString = $Matches[2] }
    elseif ($RawCommand -match '^\s*(\S+)\s*(.*)$')  { $exeToken = $Matches[1]; $argString = $Matches[2] }

    $resolvedExe = $null
    if ($exeToken) {
        if (Test-Path -LiteralPath $exeToken -PathType Leaf) { $resolvedExe = (Resolve-Path -LiteralPath $exeToken).ProviderPath }
        else {
            $cmd = Get-Command $exeToken -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($cmd) { $resolvedExe = $cmd.Source }
        }
    }

    if (-not $resolvedExe) {
        $result.Message = "Refused: '$exeToken' does not resolve to a real file on disk."
        if ($dry) { Write-Log "[DRY RUN] This command would be REFUSED ('$exeToken' is not a real file)." }
        return $result
    }
    if ([System.IO.Path]::GetExtension($resolvedExe) -ine ".exe") {
        $result.Message = "Refused: '$resolvedExe' is not an .exe file."
        if ($dry) { Write-Log "[DRY RUN] This command would be REFUSED (not an .exe: $resolvedExe)." }
        return $result
    }

    if ((Split-Path $resolvedExe -Leaf) -ieq "msiexec.exe") {
        # Some registry entries use /I{GUID}, which opens repair/modify instead of removing.
        $argString = $argString -replace '(?i)(^|\s)/I(?=\s*\{)', '$1/X'
    }

    $sig = Get-AuthenticodeSignature -LiteralPath $resolvedExe -ErrorAction SilentlyContinue
    $sigStatus = if ($sig) { $sig.Status.ToString() } else { "Unknown" }
    $signer    = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "none" }

    if ($dry) {
        Write-Log "[DRY RUN] Would run: `"$resolvedExe`" $argString"
        Write-Log "[DRY RUN]   Digital signature: $sigStatus (signer: $signer)"
        if ($sigStatus -ne "Valid") { Write-Log "[DRY RUN]   A real run would ask for explicit confirmation because the signature is not valid." }
        $result.Success = $true
        $result.Message = "dry run - not executed"
        return $result
    }

    if ($sigStatus -ne "Valid") {
        $confirm = [System.Windows.MessageBox]::Show(
            "This uninstaller is NOT validly signed:`n`nFile: $resolvedExe`nArguments: $argString`nSignature: $sigStatus (signer: $signer)`n`nMany old but legitimate uninstallers are unsigned. Run it anyway with Administrator rights?",
            "Unsigned Uninstaller", "YesNo", "Warning")
        if ($confirm -ne "Yes") { $result.Message = "Skipped by user (executable is not validly signed)."; return $result }
    }

    try {
        $proc = if ($argString) {
            Start-Process -FilePath $resolvedExe -ArgumentList $argString -Wait -NoNewWindow -PassThru
        } else {
            Start-Process -FilePath $resolvedExe -Wait -NoNewWindow -PassThru
        }
        $result.ExitCode = $proc.ExitCode
        # 0 = success; 3010 / 1641 = success but a reboot is required (common for MSI)
        $result.Success = ($proc.ExitCode -in 0, 3010, 1641)
        $result.Message = "Exit code: $($proc.ExitCode)"
    } catch {
        $result.Message = $_.Exception.Message
    }
    return $result
}

# ============================================================================
# WPF UI
# ============================================================================
[xml]$Xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="STwaek - App Installer, System Tweaks, Uninstaller &amp; Security"
        Height="780" Width="1040" WindowStartupLocation="CenterScreen"
        Background="#1e1e1e">
    <Window.Resources>
        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="Margin" Value="4,4,4,4"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>
        <Style TargetType="TextBlock">
            <Setter Property="Foreground" Value="White"/>
        </Style>
        <Style TargetType="GroupBox">
            <Setter Property="Foreground" Value="#4FC3F7"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="Margin" Value="6"/>
        </Style>
        <Style TargetType="Button">
            <Setter Property="Padding" Value="12,6"/>
            <Setter Property="Margin" Value="6"/>
            <Setter Property="FontWeight" Value="Bold"/>
        </Style>
    </Window.Resources>
    <DockPanel>
        <TextBlock DockPanel.Dock="Top" Text="STwaek" FontSize="22" FontWeight="Bold"
                   Foreground="#4FC3F7" Margin="12,10,0,0"/>
        <TextBlock DockPanel.Dock="Top" Text="App installer + reversible system tweaks + full uninstaller + Windows Defender scan (no remote access feature)"
                   FontSize="11" Foreground="#AAAAAA" Margin="12,0,0,4" TextWrapping="Wrap"/>
        <TextBlock Name="TxtDryRunBanner" DockPanel.Dock="Top" Text="DRY RUN is ON - nothing will be changed. Actions only print what they WOULD do in the Log tab."
                   FontSize="12" FontWeight="Bold" Foreground="#FFD54F" Margin="12,0,0,8" TextWrapping="Wrap"/>

        <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,8,0,10">
            <Button Name="BtnInstall" Content="Install Selected Apps" Background="#2e7d32" Foreground="White" Width="170"/>
            <Button Name="BtnTweak"   Content="Apply Selected Tweaks" Background="#1565c0" Foreground="White" Width="170"/>
            <Button Name="BtnUndo"    Content="Undo Everything This Tool Did" Background="#c62828" Foreground="White" Width="210"/>
            <CheckBox Name="ChkDryRun" Content="Dry Run (simulate only)" IsChecked="True" VerticalAlignment="Center"
                      Foreground="#FFD54F" FontWeight="Bold" Margin="14,0,0,0"/>
        </StackPanel>

        <TabControl Margin="10" Background="#252526">
            <TabItem Header="Apps">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel Name="AppsPanel" Margin="10"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Tweaks">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel Name="TweaksPanel" Margin="10"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Uninstall Apps">
                <DockPanel Margin="10">
                    <TextBlock DockPanel.Dock="Top" TextWrapping="Wrap" Margin="0,0,0,8" Foreground="#AAAAAA" FontSize="11"
                               Text="Select one or more installed apps and remove them completely. Leftover suggestions rely mainly on the program's own registered install path, plus a narrow name match in AppData/ProgramData only - never a different still-installed app's folder, and never Documents/Desktop/Pictures/Downloads/OneDrive etc. You get a checklist to confirm exactly what else to delete."/>
                    <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,8">
                        <TextBlock Text="Search:" VerticalAlignment="Center" Margin="0,0,6,0"/>
                        <TextBox Name="FilterBox" Width="220" VerticalAlignment="Center"/>
                        <Button Name="BtnRefreshUninstall" Content="Refresh List" Width="120"/>
                        <Button Name="BtnUninstallSelected" Content="Uninstall Selected" Background="#c62828" Foreground="White" Width="180"/>
                    </StackPanel>
                    <DataGrid Name="UninstallGrid" AutoGenerateColumns="False" IsReadOnly="True" SelectionMode="Extended" SelectionUnit="FullRow"
                              Background="#1e1e1e" Foreground="White" RowBackground="#252526" AlternatingRowBackground="#2d2d30"
                              HeadersVisibility="Column" GridLinesVisibility="Horizontal" CanUserAddRows="False">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Application" Binding="{Binding DisplayName}" Width="2.2*"/>
                            <DataGridTextColumn Header="Publisher" Binding="{Binding Publisher}" Width="1.3*"/>
                            <DataGridTextColumn Header="Version" Binding="{Binding DisplayVersion}" Width="*"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </DockPanel>
            </TabItem>
            <TabItem Header="Security">
                <DockPanel Margin="10">
                    <TextBlock DockPanel.Dock="Top" TextWrapping="Wrap" Margin="0,0,0,8" Foreground="#AAAAAA" FontSize="11"
                               Text="This calls Windows Defender's own built-in engine (Start-MpScan / Get-MpThreat / Remove-MpThreat). Results shown are exactly what Defender reports - nothing here is a custom scanner making its own claims."/>
                    <TextBlock Name="TxtDefenderStatus" DockPanel.Dock="Top" Text="Status: not checked yet" Margin="0,0,0,8" TextWrapping="Wrap" Foreground="#FFD54F"/>
                    <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,8">
                        <Button Name="BtnRefreshDefender" Content="Check Status" Width="140"/>
                        <Button Name="BtnQuickScan" Content="Quick Scan" Background="#1565c0" Foreground="White" Width="140"/>
                        <Button Name="BtnFullScan" Content="Full Scan (background)" Background="#1565c0" Foreground="White" Width="180"/>
                        <Button Name="BtnRemoveThreats" Content="Remove Detected Threats" Background="#c62828" Foreground="White" Width="200"/>
                    </StackPanel>
                    <DataGrid Name="ThreatGrid" AutoGenerateColumns="False" IsReadOnly="True" SelectionMode="Extended"
                              Background="#1e1e1e" Foreground="White" RowBackground="#252526" AlternatingRowBackground="#2d2d30"
                              HeadersVisibility="Column" GridLinesVisibility="Horizontal" CanUserAddRows="False">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Threat Name" Binding="{Binding ThreatName}" Width="2.5*"/>
                            <DataGridTextColumn Header="Severity" Binding="{Binding SeverityID}" Width="*"/>
                            <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="*"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </DockPanel>
            </TabItem>
            <TabItem Header="Log">
                <TextBox Name="LogBox" IsReadOnly="True" TextWrapping="Wrap" AcceptsReturn="True"
                         VerticalScrollBarVisibility="Auto" Background="#1e1e1e" Foreground="#CCCCCC"
                         FontFamily="Consolas" FontSize="12" Margin="10"/>
            </TabItem>
        </TabControl>
    </DockPanel>
</Window>
"@

$Reader = (New-Object System.Xml.XmlNodeReader $Xaml)
$Window = [Windows.Markup.XamlReader]::Load($Reader)

$AppsPanel            = $Window.FindName("AppsPanel")
$TweaksPanel          = $Window.FindName("TweaksPanel")
$LogBox               = $Window.FindName("LogBox")
$BtnInstall           = $Window.FindName("BtnInstall")
$BtnTweak             = $Window.FindName("BtnTweak")
$BtnUndo              = $Window.FindName("BtnUndo")
$ChkDryRun            = $Window.FindName("ChkDryRun")
$TxtDryRunBanner      = $Window.FindName("TxtDryRunBanner")
$FilterBox            = $Window.FindName("FilterBox")
$BtnRefreshUninstall  = $Window.FindName("BtnRefreshUninstall")
$BtnUninstallSelected = $Window.FindName("BtnUninstallSelected")
$UninstallGrid        = $Window.FindName("UninstallGrid")
$TxtDefenderStatus    = $Window.FindName("TxtDefenderStatus")
$BtnRefreshDefender   = $Window.FindName("BtnRefreshDefender")
$BtnQuickScan         = $Window.FindName("BtnQuickScan")
$BtnFullScan          = $Window.FindName("BtnFullScan")
$BtnRemoveThreats     = $Window.FindName("BtnRemoveThreats")
$ThreatGrid           = $Window.FindName("ThreatGrid")

function Write-Log {
    param([string]$Text)
    $timestamp = Get-Date -Format "HH:mm:ss"
    $LogBox.AppendText("[$timestamp] $Text`r`n")
    $LogBox.ScrollToEnd()
    $LogBox.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [action]{})
}

# Dry Run toggle: updates the banner and tells the user which mode is active.
function Update-DryRunBanner {
    if (Test-DryRun) {
        $TxtDryRunBanner.Text = "DRY RUN is ON - nothing will be changed. Actions only print what they WOULD do in the Log tab."
        $TxtDryRunBanner.Foreground = "#FFD54F"
        Write-Log "Dry Run enabled: actions are simulated only."
    } else {
        $TxtDryRunBanner.Text = "DRY RUN is OFF - actions will make REAL changes to this computer."
        $TxtDryRunBanner.Foreground = "#EF5350"
        Write-Log "Dry Run DISABLED: actions will now make real changes."
    }
}
$ChkDryRun.Add_Checked({ Update-DryRunBanner })
$ChkDryRun.Add_Unchecked({ Update-DryRunBanner })

# ----------------------------------------------------------------------------
# Leftover review dialog - per-item checkboxes, nothing is auto-selected
# blindly; shows size/file count so the user can judge each one.
# ----------------------------------------------------------------------------
function Show-LeftoverReviewDialog {
    param([array]$Items)

    [xml]$DlgXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Review Leftover Folders" Height="540" Width="760" WindowStartupLocation="CenterScreen" Background="#1e1e1e">
    <DockPanel Margin="12">
        <TextBlock DockPanel.Dock="Top" TextWrapping="Wrap" Foreground="White" Margin="0,0,0,8"
                   Text="These folders matched the uninstalled program's registered install path or exact AppData/ProgramData folder name. NOTHING is selected by default. Tick only what you are sure about. By default, ticked folders are MOVED to a quarantine folder (restorable), not erased."/>
        <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,8,0,0">
            <Button Name="BtnSelectAll" Content="Select All" Width="100" Margin="4"/>
            <Button Name="BtnSelectNone" Content="Select None" Width="100" Margin="4"/>
            <Button Name="BtnDelete" Content="Remove Checked" Background="#c62828" Foreground="White" Width="140" Margin="4"/>
            <Button Name="BtnCancel" Content="Cancel" Width="100" Margin="4"/>
        </StackPanel>
        <StackPanel DockPanel.Dock="Bottom" Margin="0,8,0,0">
            <CheckBox Name="ChkPermanent" Content="Delete permanently instead of moving to quarantine (cannot be undone)" Foreground="#FF8A80"/>
            <StackPanel Orientation="Horizontal">
                <TextBlock Text="Type DELETE to confirm:" VerticalAlignment="Center" Margin="4,0,8,0" Foreground="White"/>
                <TextBox Name="TxtConfirm" Width="140"/>
            </StackPanel>
        </StackPanel>
        <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel Name="ItemsPanel"/>
        </ScrollViewer>
    </DockPanel>
</Window>
"@
    $dlgReader = New-Object System.Xml.XmlNodeReader $DlgXaml
    $dlg = [Windows.Markup.XamlReader]::Load($dlgReader)
    $itemsPanel   = $dlg.FindName("ItemsPanel")
    $btnAll       = $dlg.FindName("BtnSelectAll")
    $btnNone      = $dlg.FindName("BtnSelectNone")
    $btnDelete    = $dlg.FindName("BtnDelete")
    $btnCancel    = $dlg.FindName("BtnCancel")
    $chkPermanent = $dlg.FindName("ChkPermanent")
    $txtConfirm   = $dlg.FindName("TxtConfirm")

    $checkboxMap = @{}
    foreach ($item in $Items) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Foreground = "White"
        $cb.Margin = "2"
        $cb.Content = "{0}   ({1} MB, {2} file(s))" -f $item.Path, $item.SizeMB, $item.FileCount
        $cb.IsChecked = $false
        $checkboxMap[$cb] = $item.Path
        $itemsPanel.Children.Add($cb) | Out-Null
    }

    $script:LeftoverDialogResult = [PSCustomObject]@{ Paths = @(); Permanent = $false }
    $btnAll.Add_Click({ foreach ($cb in $checkboxMap.Keys) { $cb.IsChecked = $true } })
    $btnNone.Add_Click({ foreach ($cb in $checkboxMap.Keys) { $cb.IsChecked = $false } })
    $btnCancel.Add_Click({ $script:LeftoverDialogResult = [PSCustomObject]@{ Paths = @(); Permanent = $false }; $dlg.Close() })
    $btnDelete.Add_Click({
        $chosen = @($checkboxMap.Keys | Where-Object { $_.IsChecked -eq $true } | ForEach-Object { $checkboxMap[$_] })
        if ($chosen.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Nothing is ticked.", "Remove Checked", "OK", "Information") | Out-Null
            return
        }
        if ($txtConfirm.Text -cne "DELETE") {
            [System.Windows.MessageBox]::Show("Type DELETE exactly (capital letters) in the confirmation box to continue.", "Confirmation required", "OK", "Warning") | Out-Null
            return
        }
        $script:LeftoverDialogResult = [PSCustomObject]@{ Paths = $chosen; Permanent = ($chkPermanent.IsChecked -eq $true) }
        $dlg.Close()
    })

    $dlg.ShowDialog() | Out-Null
    return $script:LeftoverDialogResult
}

# Build Apps tab grouped by category
$appCheckboxMap = @{}
$categories = $AppCatalog | ForEach-Object { $_.Cat } | Sort-Object -Unique
foreach ($cat in $categories) {
    $group = New-Object System.Windows.Controls.GroupBox
    $group.Header = $cat
    $group.Foreground = "#4FC3F7"
    $panel = New-Object System.Windows.Controls.WrapPanel
    foreach ($app in ($AppCatalog | Where-Object { $_.Cat -eq $cat })) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = $app.Name
        $cb.Width = 220
        $appCheckboxMap[$cb] = $app
        $panel.Children.Add($cb) | Out-Null
    }
    $group.Content = $panel
    $AppsPanel.Children.Add($group) | Out-Null
}

# Build Tweaks tab
$tweakCheckboxMap = @{}
$tweakGroup = New-Object System.Windows.Controls.GroupBox
$tweakGroup.Header = "System Tweaks (each one restores its OWN previous value on Undo)"
$tweakGroup.Foreground = "#4FC3F7"
$tweakStack = New-Object System.Windows.Controls.StackPanel
foreach ($tweak in $TweakCatalog) {
    $cb = New-Object System.Windows.Controls.CheckBox
    $cb.Content = $tweak.Name
    $tweakCheckboxMap[$cb] = $tweak
    $tweakStack.Children.Add($cb) | Out-Null
}
$tweakGroup.Content = $tweakStack
$TweaksPanel.Children.Add($tweakGroup) | Out-Null

# ----------------------------------------------------------------------------
# Uninstall tab logic
# ----------------------------------------------------------------------------
$script:AllPrograms = @()

function Apply-UninstallFilter {
    $filter = $FilterBox.Text
    if ([string]::IsNullOrWhiteSpace($filter)) {
        $UninstallGrid.ItemsSource = $script:AllPrograms
    } else {
        $UninstallGrid.ItemsSource = @($script:AllPrograms | Where-Object { $_.DisplayName -like "*$filter*" })
    }
}

function Update-UninstallGrid {
    Write-Log "Scanning installed programs ..."
    $script:AllPrograms = @(Get-InstalledPrograms)
    Apply-UninstallFilter
    Write-Log "Found $($script:AllPrograms.Count) installed program(s)."
}

$FilterBox.Add_TextChanged({ Apply-UninstallFilter })
$BtnRefreshUninstall.Add_Click({ Update-UninstallGrid })

$BtnUninstallSelected.Add_Click({
    $selected = @($UninstallGrid.SelectedItems)
    if ($selected.Count -eq 0) { Write-Log "No application selected to uninstall."; return }

    $dry = Test-DryRun

    if (-not $dry) {
        $names = ($selected | ForEach-Object { $_.DisplayName }) -join "`n - "
        $confirm = [System.Windows.MessageBox]::Show(
            "This will run the official uninstaller for:`n - $names`n`nAfterward you'll get a checklist of any leftover folders found, so you choose exactly what else to remove. Continue?",
            "Uninstall Selected", "YesNo", "Warning")
        if ($confirm -ne "Yes") { return }
    } else {
        Write-Log "[DRY RUN] Simulating uninstall of $($selected.Count) application(s). Nothing will be removed."
    }

    # Paths belonging to apps NOT being uninstalled right now - never offered
    # as "leftovers" even if a name happens to match.
    $selectedNames = $selected | ForEach-Object { $_.DisplayName }
    $otherInstallLocations = @(
        $script:AllPrograms |
            Where-Object { $_.DisplayName -notin $selectedNames -and $_.InstallLocation } |
            Select-Object -ExpandProperty InstallLocation
    )

    $allLeftovers = @()
    foreach ($app in $selected) {
        $cmd = if ($app.QuietUninstallString) { $app.QuietUninstallString } else { $app.UninstallString }
        if ($dry) {
            Write-Log "[DRY RUN] $($app.DisplayName) (version $($app.DisplayVersion), publisher $($app.Publisher))"
            Write-Log "[DRY RUN]   Registered uninstall command: $cmd"
        } else {
            Write-Log "Uninstalling $($app.DisplayName) ..."
        }
        if ([string]::IsNullOrWhiteSpace($cmd)) { Write-Log "No uninstall command found for $($app.DisplayName), skipping."; continue }

        $result = Invoke-UninstallCommand -RawCommand $cmd
        if ($result.Success) {
            if (-not $dry) { Write-Log "Uninstaller finished for $($app.DisplayName). ($($result.Message))" }
        } else {
            Write-Log "Uninstaller for $($app.DisplayName) did NOT confirm success ($($result.Message)). Skipping leftover scan for it to be safe."
            continue
        }

        # The leftover scan only READS the disk, so it is safe to run in Dry Run
        # as well - it shows exactly which folders would be offered afterwards.
        $leftovers = @(Find-LeftoverPaths -App $app -OtherInstallLocations $otherInstallLocations)
        if ($leftovers.Count -gt 0) {
            Write-Log "Found $($leftovers.Count) possible leftover folder(s) for $($app.DisplayName)."
            $allLeftovers += $leftovers
        }
    }

    if ($dry) {
        if ($allLeftovers.Count -gt 0) {
            Write-Log "[DRY RUN] These folders would be offered (unticked, DELETE confirmation required, moved to quarantine by default). Nothing was touched:"
            foreach ($l in $allLeftovers) {
                Write-Log ("[DRY RUN]   {0}   ({1} MB, {2} file(s))" -f $l.Path, $l.SizeMB, $l.FileCount)
            }
        } else {
            Write-Log "[DRY RUN] No leftover folders would be offered."
        }
        Write-Log "[DRY RUN] Done. No program was uninstalled and no file was deleted."
        return
    }

    if ($allLeftovers.Count -gt 0) {
        $choice = Show-LeftoverReviewDialog -Items $allLeftovers
        if ($choice.Paths.Count -gt 0) {
            foreach ($path in $choice.Paths) {
                Remove-LeftoverSafely -Path $path -OtherInstallLocations $otherInstallLocations -Permanent $choice.Permanent | Out-Null
            }
        } else {
            Write-Log "No leftover folders were selected for removal."
        }
    } else {
        Write-Log "No leftover folders found."
    }

    Update-UninstallGrid
})

# ----------------------------------------------------------------------------
# Security tab logic (Windows Defender)
# ----------------------------------------------------------------------------
function Get-DefenderStatusText {
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        return "Real-time protection: $($s.RealTimeProtectionEnabled) | Antivirus enabled: $($s.AntivirusEnabled) | Signatures updated: $($s.AntivirusSignatureLastUpdated) | Last quick scan age: $($s.QuickScanAge) day(s) | Last full scan age: $($s.FullScanAge) day(s)"
    } catch {
        return "Windows Defender status unavailable on this system: $($_.Exception.Message)"
    }
}

function Update-ThreatGrid {
    try {
        $threats = @(Get-MpThreat -ErrorAction Stop)
        $ThreatGrid.ItemsSource = @($threats | Select-Object ThreatID, ThreatName, SeverityID, @{N='Status';E={$_.CurrentStatus}})
        if ($threats.Count -gt 0) { Write-Log "Windows Defender currently lists $($threats.Count) active threat(s)." }
        else { Write-Log "Windows Defender reports no active threats detected." }
    } catch {
        Write-Log "Could not query Windows Defender threats: $($_.Exception.Message)"
    }
}

$BtnRefreshDefender.Add_Click({ $TxtDefenderStatus.Text = "Status: " + (Get-DefenderStatusText) })

$BtnQuickScan.Add_Click({
    if (Test-DryRun) {
        Write-Log "[DRY RUN] Would run: Start-MpScan -ScanType QuickScan (not started; Defender may quarantine items during a real scan)."
        return
    }
    Write-Log "Starting Windows Defender Quick Scan (this window will be busy for a bit) ..."
    try {
        Start-MpScan -ScanType QuickScan -ErrorAction Stop
        Write-Log "Quick scan finished."
        Update-ThreatGrid
    } catch {
        Write-Log "Quick scan failed: $($_.Exception.Message)"
    }
})

$script:FullScanJob = $null
$FullScanTimer = New-Object System.Windows.Threading.DispatcherTimer
$FullScanTimer.Interval = [TimeSpan]::FromSeconds(5)
$FullScanTimer.Add_Tick({
    if ($script:FullScanJob -and $script:FullScanJob.State -ne 'Running') {
        $FullScanTimer.Stop()
        $jobErrors = $null
        try { Receive-Job -Job $script:FullScanJob -ErrorVariable jobErrors -ErrorAction SilentlyContinue | Out-Null } catch { }
        if ($script:FullScanJob.State -eq 'Completed' -and -not $jobErrors) {
            Write-Log "Full scan completed successfully."
        } else {
            $errText = if ($jobErrors) { ($jobErrors -join "; ") } else { "no further detail" }
            Write-Log "Full scan finished with state '$($script:FullScanJob.State)' - $errText."
        }
        Remove-Job -Job $script:FullScanJob -ErrorAction SilentlyContinue
        $script:FullScanJob = $null
        Update-ThreatGrid
    }
})

$BtnFullScan.Add_Click({
    if (Test-DryRun) {
        Write-Log "[DRY RUN] Would start: Start-MpScan -ScanType FullScan in a background job (not started)."
        return
    }
    if ($script:FullScanJob) { Write-Log "A full scan is already running in the background."; return }
    Write-Log "Starting Windows Defender Full Scan in the background (this can take a long time; you can keep using the tool meanwhile) ..."
    try {
        $script:FullScanJob = Start-Job -ScriptBlock { Start-MpScan -ScanType FullScan }
        $FullScanTimer.Start()
    } catch {
        Write-Log "Could not start full scan: $($_.Exception.Message)"
    }
})

$BtnRemoveThreats.Add_Click({
    if (Test-DryRun) {
        try {
            $found = @(Get-MpThreat -ErrorAction Stop)
            if ($found.Count -eq 0) {
                Write-Log "[DRY RUN] Defender lists no threats; Remove-MpThreat would have nothing to do."
            } else {
                Write-Log "[DRY RUN] Would run Remove-MpThreat. Threats Defender currently lists ($($found.Count)):"
                foreach ($t in $found) { Write-Log "[DRY RUN]   $($t.ThreatName) (severity $($t.SeverityID))" }
            }
        } catch {
            Write-Log "[DRY RUN] Could not query Defender threats: $($_.Exception.Message)"
        }
        return
    }
    try {
        $before = @(Get-MpThreat -ErrorAction SilentlyContinue).Count
        if ($before -eq 0) { Write-Log "No active threats to remove."; return }
        Remove-MpThreat -ErrorAction Stop
        Write-Log "Requested removal/quarantine of all threats currently flagged by Windows Defender."
    } catch {
        Write-Log "Could not remove threats automatically: $($_.Exception.Message). Try the Windows Security app's Protection History instead."
    }
    Update-ThreatGrid
})

# ----------------------------------------------------------------------------
# Install / Tweak / Undo button actions
# ----------------------------------------------------------------------------
function Test-WingetInstalled($Id) {
    try {
        & winget list --id $Id -e --accept-source-agreements 2>&1 | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

$BtnInstall.Add_Click({
    $selected = $appCheckboxMap.Keys | Where-Object { $_.IsChecked -eq $true }
    if (-not $selected) { Write-Log "No apps selected."; return }
    $dry = Test-DryRun
    foreach ($cb in $selected) {
        $app = $appCheckboxMap[$cb]
        $already = Test-WingetInstalled $app.Id
        if ($dry) {
            if ($already) {
                Write-Log "[DRY RUN] $($app.Name) is ALREADY installed - a real run would skip it and would NOT record it, so Undo can never remove it."
            } else {
                Write-Log "[DRY RUN] Would run: winget install --id $($app.Id) -e --silent --accept-package-agreements --accept-source-agreements   ($($app.Name))"
            }
            continue
        }
        if ($already) {
            Write-Log "$($app.Name) is already installed - skipped, and NOT recorded (Undo will never remove a program that was there before)."
            continue
        }
        Write-Log "Installing $($app.Name) ..."
        try {
            $proc = Start-Process -FilePath "winget" -ArgumentList "install --id $($app.Id) -e --silent --accept-package-agreements --accept-source-agreements" -Wait -NoNewWindow -PassThru
            if ($proc.ExitCode -eq 0 -and (Test-WingetInstalled $app.Id)) {
                Add-InstalledApp -wingetId $app.Id -displayName $app.Name
                Write-Log "Installed $($app.Name) (exit code 0, verified with winget list)."
            } else {
                Write-Log "winget returned exit code $($proc.ExitCode) for $($app.Name), or the install could not be verified - NOT recorded in the undo log."
            }
        } catch {
            Write-Log "FAILED to install $($app.Name): $($_.Exception.Message)"
        }
    }
    if ($dry) { Write-Log "[DRY RUN] Done. Nothing was installed and the action log was not modified." }
    else { Write-Log "Done installing selected apps." }
})

$BtnTweak.Add_Click({
    $selected = $tweakCheckboxMap.Keys | Where-Object { $_.IsChecked -eq $true }
    if (-not $selected) { Write-Log "No tweaks selected."; return }
    $dry = Test-DryRun
    foreach ($cb in $selected) {
        $tweak = $tweakCheckboxMap[$cb]

        if ($dry) {
            # Reading current state is harmless; Apply is never called and
            # nothing is written to the action log.
            Write-Log "[DRY RUN] $($tweak.Name)"
            try {
                $state = & $tweak.GetState
                foreach ($line in @(& $tweak.Plan $state)) { Write-Log "[DRY RUN]   $line" }
            } catch {
                Write-Log "[DRY RUN]   Could not read current state: $($_.Exception.Message)"
            }
            continue
        }

        Write-Log "Applying tweak: $($tweak.Name) ..."
        # Capture AND persist the pre-tweak state BEFORE calling Apply. If Apply
        # throws partway through a multi-step change, the undo record for what
        # was already changed still exists - it's not lost in the catch block.
        $state = & $tweak.GetState
        Add-AppliedTweak -tweakKey $tweak.Key -displayName $tweak.Name -state $state
        try {
            $extra = & $tweak.Apply
            if ($extra) { Merge-AppliedTweakExtraState -tweakKey $tweak.Key -extra $extra }
            Write-Log "Applied: $($tweak.Name)"
        } catch {
            Write-Log "FAILED to fully apply $($tweak.Name): $($_.Exception.Message) - any partial changes already have their previous state recorded, so Undo can still restore safely."
        }
    }
    if ($dry) { Write-Log "[DRY RUN] Done. No setting was changed and the action log was not modified." }
    else { Write-Log "Done applying selected tweaks. Some tweaks may require sign-out/restart to take visible effect." }
})

# True when the CURRENT state (from GetState) matches what was saved before the
# tweak was applied. Only keys present in both are compared.
function Test-StateRestored($Saved, $Current) {
    $s = ConvertTo-HashtableDeep $Saved
    $c = ConvertTo-HashtableDeep $Current
    foreach ($k in $s.Keys) {
        if (-not $c.ContainsKey($k)) { continue }
        $sv = $s[$k]; $cv = $c[$k]
        if ($sv -is [System.Management.Automation.PSCustomObject] -or $sv -is [System.Collections.IDictionary]) {
            $a = ConvertTo-HashtableDeep $sv
            $b = ConvertTo-HashtableDeep $cv
            if ([bool]$a.Exists -ne [bool]$b.Exists) { return $false }
            if ($a.Exists -and ("$($a.Value)" -ne "$($b.Value)")) { return $false }
        } elseif ("$sv" -ne "$cv") {
            return $false
        }
    }
    return $true
}

$BtnUndo.Add_Click({
    $dry = Test-DryRun

    if (-not $dry) {
        $confirm = [System.Windows.MessageBox]::Show(
            "This will uninstall every app STwaek installed and restore every tweak STwaek applied back to its exact previous value. It will NOT touch anything else on the system. Anything that cannot be undone successfully stays in the action log so you can retry. Continue?",
            "Undo Everything This Tool Did", "YesNo", "Warning")
        if ($confirm -ne "Yes") { return }
    }

    $log = Get-ActionLog

    if ($dry) {
        $apps   = @($log.installedApps)
        $tweaks = @($log.appliedTweaks)
        Write-Log "[DRY RUN] Undo preview: $($apps.Count) installed app(s) and $($tweaks.Count) applied tweak(s) recorded in the action log."
        foreach ($app in $apps) {
            Write-Log "[DRY RUN] Would run: winget uninstall --id $($app.id) -e --silent   ($($app.name), installed $($app.date))"
        }
        foreach ($t in $tweaks) {
            $def = $TweakCatalog | Where-Object { $_.Key -eq $t.key }
            if ($def) {
                Write-Log "[DRY RUN] Would restore: $($t.name) (applied $($t.date))"
                foreach ($line in @(Format-SavedState $t.state)) { Write-Log "[DRY RUN]   $line" }
            } else {
                Write-Log "[DRY RUN] Recorded tweak '$($t.key)' has no matching definition in this version; it would be skipped and KEPT in the log."
            }
        }
        Write-Log "[DRY RUN] Done. Nothing was uninstalled or restored and the action log was NOT modified."
        return
    }

    $kept = 0

    foreach ($app in @($log.installedApps)) {
        Write-Log "Uninstalling $($app.name) ..."
        $removed = $false
        try {
            $proc = Start-Process -FilePath "winget" -ArgumentList "uninstall --id $($app.id) -e --silent" -Wait -NoNewWindow -PassThru
            if ($proc.ExitCode -eq 0) {
                $removed = $true
            } elseif ($proc.ExitCode -eq -1978335212) {
                # 0x8A150014: no installed package matches - already gone
                Write-Log "$($app.name) was not installed any more."
                $removed = $true
            } else {
                Write-Log "winget returned exit code $($proc.ExitCode) uninstalling $($app.name). It stays in the action log so you can retry."
            }
        } catch {
            Write-Log "FAILED to uninstall $($app.name): $($_.Exception.Message). It stays in the action log."
        }
        if ($removed -and (Test-WingetInstalled $app.id)) {
            Write-Log "$($app.name) is still listed by winget after uninstalling. It stays in the action log."
            $removed = $false
        }
        if ($removed) {
            Remove-InstalledAppEntry $app.id
            Write-Log "Uninstalled $($app.name) and removed it from the action log."
        } else { $kept++ }
    }

    foreach ($t in @($log.appliedTweaks)) {
        $def = $TweakCatalog | Where-Object { $_.Key -eq $t.key }
        if (-not $def) {
            Write-Log "No definition for recorded tweak '$($t.key)' in this version - kept in the action log."
            $kept++
            continue
        }
        Write-Log "Restoring previous value for: $($t.name) ..."
        try {
            & $def.Restore $t.state
            Start-Sleep -Milliseconds 800
            $now = & $def.GetState
            if (Test-StateRestored -Saved $t.state -Current $now) {
                Remove-AppliedTweakEntry $t.key
                Write-Log "Restored and verified: $($t.name)"
            } else {
                Write-Log "The restore ran for $($t.name), but the current state does NOT match the saved one. Kept in the action log so you can retry."
                $kept++
            }
        } catch {
            Write-Log "FAILED to restore $($t.name): $($_.Exception.Message). Kept in the action log."
            $kept++
        }
    }

    if ($kept -eq 0) { Write-Log "Undo complete. Every item was reverted and verified; the action log is now empty." }
    else { Write-Log "Undo finished, but $kept item(s) could not be reverted and remain in the action log. Run Undo again after fixing the problem." }
})

Write-Log "STwaek ready. $($AppCatalog.Count) apps and $($TweakCatalog.Count) tweaks loaded."
Write-Log "Action log stored at: $LogFile"
Write-Log "Dry Run is ON by default. Uncheck 'Dry Run' at the bottom to make real changes."

Update-UninstallGrid
$TxtDefenderStatus.Text = "Status: " + (Get-DefenderStatusText)

$Window.ShowDialog() | Out-Null
