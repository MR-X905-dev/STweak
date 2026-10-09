#Requires -RunAsAdministrator
<#
    STweak - Windows App Installer & Tweak Tool
    Inspired by Chris Titus Tech's WinUtil (https://christitus.com/win)

    - Install apps via winget, grouped by category
    - Apply safe, reversible, commonly-recommended system tweaks
    - Uninstall tab: remove installed programs + leftover folders
    - "Undo Everything" button: uninstalls every app this tool installed and
      reverts every tweak this tool applied (log-based, not a full system wipe)

    No remote-control / remote-screen feature is included in this tool.
#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# ----------------------------------------------------------------------------
# Paths / logging
# ----------------------------------------------------------------------------
$LogDir  = Join-Path $env:ProgramData "STweak"
$LogFile = Join-Path $LogDir "actions.json"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
if (-not (Test-Path $LogFile)) {
    @{ installedApps = @(); appliedTweaks = @() } | ConvertTo-Json | Set-Content -Path $LogFile -Encoding UTF8
}

function Get-ActionLog { Get-Content -Path $LogFile -Raw | ConvertFrom-Json }
function Save-ActionLog($log) { $log | ConvertTo-Json -Depth 5 | Set-Content -Path $LogFile -Encoding UTF8 }

function Add-InstalledApp($wingetId, $displayName) {
    $log  = Get-ActionLog
    $list = @($log.installedApps)
    if (-not ($list | Where-Object { $_.id -eq $wingetId })) {
        $list += [PSCustomObject]@{ id = $wingetId; name = $displayName }
    }
    $log.installedApps = $list
    Save-ActionLog $log
}

function Add-AppliedTweak($tweakKey, $displayName) {
    $log  = Get-ActionLog
    $list = @($log.appliedTweaks)
    if (-not ($list | Where-Object { $_.key -eq $tweakKey })) {
        $list += [PSCustomObject]@{ key = $tweakKey; name = $displayName }
    }
    $log.appliedTweaks = $list
    Save-ActionLog $log
}

# ----------------------------------------------------------------------------
# App catalog (winget IDs), grouped by category
# ----------------------------------------------------------------------------
function App($Name, $Id, $Cat) { [PSCustomObject]@{ Name = $Name; Id = $Id; Cat = $Cat } }

$AppCatalog = @(
    # Browsers
    (App "Google Chrome"        "Google.Chrome"                "Browsers")
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
    (App "WinSCP"               "WinSCP.WinSCP"                "Networking")

    # Virtualization
    (App "VirtualBox"           "Oracle.VirtualBox"            "Virtualization")
)

# ----------------------------------------------------------------------------
# Tweak catalog - commonly recommended, safe & reversible tweaks.
# ----------------------------------------------------------------------------
$TweakCatalog = @(
    @{ Key = "DisableTelemetry"; Name = "Disable Windows Telemetry"
        Apply = {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
        }
        Undo = { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue }
    },
    @{ Key = "DisableAdvertisingID"; Name = "Disable Advertising ID"
        Apply = {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord
        }
        Undo = { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue }
    },
    @{ Key = "DisableActivityHistory"; Name = "Disable Activity History / Timeline"
        Apply = {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type DWord
        }
        Undo = {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        }
    },
    @{ Key = "DisableLocationTracking"; Name = "Disable Location Tracking"
        Apply = {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord
        }
        Undo = { Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 0 -Type DWord -ErrorAction SilentlyContinue }
    },
    @{ Key = "DisableCortanaWebSearch"; Name = "Disable Web Search in Start Menu"
        Apply = {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type DWord
        }
        Undo = { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue }
    },
    @{ Key = "DisableGameBar"; Name = "Disable Xbox Game Bar / Game DVR"
        Apply = {
            New-Item -Path "HKCU:\System\GameConfigStore" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord
        }
        Undo = { Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue }
    },
    @{ Key = "DisableBackgroundApps"; Name = "Disable Background Running Apps"
        Apply = {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 -Type DWord
        }
        Undo = { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue }
    },
    @{ Key = "DisableSysMain"; Name = "Disable SysMain / Superfetch (recommended for SSDs)"
        Apply = { Stop-Service -Name SysMain -Force -ErrorAction SilentlyContinue; Set-Service -Name SysMain -StartupType Disabled -ErrorAction SilentlyContinue }
        Undo  = { Set-Service -Name SysMain -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service -Name SysMain -ErrorAction SilentlyContinue }
    },
    @{ Key = "DisableHibernation"; Name = "Disable Hibernation (frees disk space)"
        Apply = { powercfg /hibernate off }
        Undo  = { powercfg /hibernate on }
    },
    @{ Key = "DisableFastStartup"; Name = "Disable Fast Startup"
        Apply = { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -Type DWord }
        Undo  = { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue }
    },
    @{ Key = "UltimatePerformancePlan"; Name = "Enable Ultimate Performance Power Plan"
        Apply = {
            $out = powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-String
            if ($out -match '([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})') {
                powercfg -setactive $Matches[1]
            }
        }
        Undo = { powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e }
    },
    @{ Key = "DisableStartupDelay"; Name = "Disable Startup App Delay"
        Apply = {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Value 0 -Type DWord
        }
        Undo = { Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -ErrorAction SilentlyContinue }
    },
    @{ Key = "DisableWindowsUpdateAutoRestart"; Name = "Disable Windows Update Auto-Restart While Logged In"
        Apply = {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord
        }
        Undo = { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue }
    },
    @{ Key = "ShowFileExtensions"; Name = "Show File Extensions in Explorer"
        Apply = { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord }
        Undo  = { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1 -Type DWord }
    },
    @{ Key = "ShowHiddenFiles"; Name = "Show Hidden Files"
        Apply = { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Type DWord }
        Undo  = { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 2 -Type DWord }
    },
    @{ Key = "ShowThisPCOnDesktop"; Name = "Show 'This PC' Icon on Desktop"
        Apply = {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Type DWord
        }
        Undo  = { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 1 -Type DWord -ErrorAction SilentlyContinue }
    },
    @{ Key = "DarkMode"; Name = "Enable Dark Mode (Apps + System)"
        Apply = {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Type DWord
        }
        Undo = {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 1 -Type DWord
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 1 -Type DWord
        }
    },
    @{ Key = "AlignTaskbarLeft"; Name = "Align Taskbar Icons to the Left (Windows 11)"
        Apply = { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Type DWord }
        Undo  = { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 1 -Type DWord -ErrorAction SilentlyContinue }
    },
    @{ Key = "ClassicRightClickMenu"; Name = "Restore Classic Right-Click Menu (Windows 11)"
        Apply = {
            New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(default)" -Value "" -Type String
        }
        Undo = { Remove-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Recurse -Force -ErrorAction SilentlyContinue }
    },
    @{ Key = "DisableStickyKeysPrompt"; Name = "Disable Sticky Keys Shortcut Prompt"
        Apply = { Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "58" -Type String }
        Undo  = { Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "510" -Type String -ErrorAction SilentlyContinue }
    }
)

# ----------------------------------------------------------------------------
# Uninstall tab logic
# ----------------------------------------------------------------------------
function Get-InstalledPrograms {
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $raw = foreach ($p in $uninstallPaths) {
        Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
    }

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
        } |
        Sort-Object DisplayName
}

function Find-LeftoverPaths {
    param($App)

    $nameGuess = ($App.DisplayName -replace '[^\w\s]', '').Trim()
    # Too-short names would match unrelated folders, so skip them
    if ([string]::IsNullOrWhiteSpace($nameGuess) -or $nameGuess.Length -lt 4) { return @() }

    $roots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        $env:LOCALAPPDATA,
        $env:APPDATA
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    $found = @()
    foreach ($root in $roots) {
        # Match on the app name only. Matching on Publisher would also hit
        # shared folders (e.g. every "Microsoft*" folder), which is unsafe.
        $found += Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*$nameGuess*" } |
            Select-Object -ExpandProperty FullName
    }

    if ($App.InstallLocation -and (Test-Path $App.InstallLocation)) {
        $loc = $App.InstallLocation.TrimEnd('\')
        # Never queue a root folder (e.g. C:\Program Files) or a drive root
        if (($roots -notcontains $loc) -and ($loc.Length -gt 3)) { $found += $loc }
    }

    $found | Select-Object -Unique
}

# ----------------------------------------------------------------------------
# WPF UI
# ----------------------------------------------------------------------------
[xml]$Xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="STweak - App Installer, System Tweaks &amp; Full Uninstaller"
        Height="760" Width="1020" WindowStartupLocation="CenterScreen"
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
        <TextBlock DockPanel.Dock="Top" Text="STweak" FontSize="22" FontWeight="Bold"
                   Foreground="#4FC3F7" Margin="12,10,0,0"/>
        <TextBlock DockPanel.Dock="Top" Text="App installer + safe reversible system tweaks + full app uninstaller (no remote access feature)"
                   FontSize="11" Foreground="#AAAAAA" Margin="12,0,0,10"/>

        <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,8,0,10">
            <Button Name="BtnApply"   Content="Apply Selected (Apps + Tweaks)" Background="#2e7d32" Foreground="White" Width="240"/>
            <Button Name="BtnUndo"    Content="Undo Everything This Tool Did" Background="#c62828" Foreground="White" Width="220"/>
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
                    <TextBlock DockPanel.Dock="Top" Text="Select one or more installed apps, then remove them completely (uninstaller + leftover files/folders)."
                               FontSize="11" Foreground="#AAAAAA" Margin="0,0,0,8" TextWrapping="Wrap"/>
                    <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,8">
                        <TextBlock Text="Search:" VerticalAlignment="Center" Margin="0,0,6,0"/>
                        <TextBox Name="FilterBox" Width="220" VerticalAlignment="Center"/>
                        <Button Name="BtnRefreshUninstall" Content="Refresh List" Width="120"/>
                        <Button Name="BtnUninstallSelected" Content="Uninstall Selected (Deep Clean)" Background="#c62828" Foreground="White" Width="230"/>
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
            <TabItem Header="Log">
                <TextBox Name="LogBox" IsReadOnly="True" TextWrapping="Wrap" AcceptsReturn="True"
                         VerticalScrollBarVisibility="Auto" Background="#1e1e1e" Foreground="#CCCCCC"
                         FontFamily="Consolas" FontSize="12" Margin="10"/>
            </TabItem>
        </TabControl>
    </DockPanel>
</Window>
"@

$Reader = New-Object System.Xml.XmlNodeReader $Xaml
$Window = [Windows.Markup.XamlReader]::Load($Reader)

$AppsPanel            = $Window.FindName("AppsPanel")
$TweaksPanel          = $Window.FindName("TweaksPanel")
$LogBox               = $Window.FindName("LogBox")
$BtnApply             = $Window.FindName("BtnApply")
$BtnUndo              = $Window.FindName("BtnUndo")
$FilterBox            = $Window.FindName("FilterBox")
$BtnRefreshUninstall  = $Window.FindName("BtnRefreshUninstall")
$BtnUninstallSelected = $Window.FindName("BtnUninstallSelected")
$UninstallGrid        = $Window.FindName("UninstallGrid")

$AccentBrush = (New-Object System.Windows.Media.BrushConverter).ConvertFromString("#4FC3F7")

function Write-Log {
    param([string]$Text)
    $timestamp = Get-Date -Format "HH:mm:ss"
    $LogBox.AppendText("[$timestamp] $Text`r`n")
    $LogBox.ScrollToEnd()
    $LogBox.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [action]{})
}

# Build Apps tab grouped by category
$appCheckboxMap = @{}
$categories = $AppCatalog | ForEach-Object { $_.Cat } | Sort-Object -Unique
foreach ($cat in $categories) {
    $group = New-Object System.Windows.Controls.GroupBox
    $group.Header = $cat
    $group.Foreground = $AccentBrush
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
$tweakGroup.Header = "System Tweaks (safe & reversible)"
$tweakGroup.Foreground = $AccentBrush
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
# Uninstall tab handlers
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

    $names = ($selected | ForEach-Object { $_.DisplayName }) -join "`n"
    $confirm = [System.Windows.MessageBox]::Show(
        "This will run the official uninstaller for:`n`n$names`n`nAfterward, STweak will look for leftover files/folders and offer to delete those too. Continue?",
        "Uninstall Selected", "YesNo", "Warning")
    if ($confirm -ne "Yes") { return }

    $allLeftovers = @()

    foreach ($app in $selected) {
        Write-Log "Uninstalling $($app.DisplayName) ..."
        $cmd = if ($app.QuietUninstallString) { $app.QuietUninstallString } else { $app.UninstallString }
        if ([string]::IsNullOrWhiteSpace($cmd)) {
            Write-Log "No uninstall command found for $($app.DisplayName), skipping."
            continue
        }
        try {
            Start-Process -FilePath $env:ComSpec -ArgumentList "/c `"$cmd`"" -Wait -NoNewWindow
            Write-Log "Uninstaller finished for $($app.DisplayName)."
        } catch {
            Write-Log "FAILED to run uninstaller for $($app.DisplayName): $($_.Exception.Message)"
        }

        $leftovers = @(Find-LeftoverPaths -App $app)
        if ($leftovers.Count -gt 0) {
            Write-Log "Found $($leftovers.Count) possible leftover folder(s) for $($app.DisplayName)."
            $allLeftovers += $leftovers
        }
    }

    $allLeftovers = @($allLeftovers | Select-Object -Unique)
    if ($allLeftovers.Count -gt 0) {
        $list = $allLeftovers -join "`n"
        $confirmDelete = [System.Windows.MessageBox]::Show(
            "Delete these leftover folders too?`n`n$list",
            "Delete Leftovers", "YesNo", "Warning")
        if ($confirmDelete -eq "Yes") {
            foreach ($path in $allLeftovers) {
                try {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                    Write-Log "Deleted leftover: $path"
                } catch {
                    Write-Log "FAILED to delete ${path}: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Log "Leftover folders kept (user declined deletion)."
        }
    } else {
        Write-Log "No leftover folders found."
    }

    Update-UninstallGrid
})

# ----------------------------------------------------------------------------
# Button actions
# ----------------------------------------------------------------------------
function Install-SelectedApps {
    $selected = @($appCheckboxMap.Keys | Where-Object { $_.IsChecked -eq $true })
    if ($selected.Count -eq 0) { return }
    foreach ($cb in $selected) {
        $app = $appCheckboxMap[$cb]

        # If the app is already installed, do not track it, so Undo never removes it
        & winget list --id $app.Id -e --accept-source-agreements 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "$($app.Name) is already installed - skipped (not tracked for undo)."
            continue
        }

        Write-Log "Installing $($app.Name) ..."
        try {
            $p = Start-Process -FilePath "winget" -ArgumentList "install --id $($app.Id) -e --silent --accept-package-agreements --accept-source-agreements" -Wait -NoNewWindow -PassThru
            if ($p.ExitCode -eq 0) {
                Add-InstalledApp -wingetId $app.Id -displayName $app.Name
                Write-Log "Installed $($app.Name)."
            } else {
                Write-Log "FAILED to install $($app.Name) (winget exit code $($p.ExitCode))."
            }
        } catch {
            Write-Log "FAILED to install $($app.Name): $($_.Exception.Message)"
        }
    }
}

function Apply-SelectedTweaks {
    $selected = @($tweakCheckboxMap.Keys | Where-Object { $_.IsChecked -eq $true })
    if ($selected.Count -eq 0) { return }
    foreach ($cb in $selected) {
        $tweak = $tweakCheckboxMap[$cb]
        Write-Log "Applying tweak: $($tweak.Name) ..."
        try {
            & $tweak.Apply
            Add-AppliedTweak -tweakKey $tweak.Key -displayName $tweak.Name
            Write-Log "Applied tweak: $($tweak.Name)."
        } catch {
            Write-Log "FAILED to apply tweak $($tweak.Name): $($_.Exception.Message)"
        }
    }
    Write-Log "Some tweaks take effect after restarting Explorer or signing out/in."
}

$BtnApply.Add_Click({
    $anyApps   = @($appCheckboxMap.Keys   | Where-Object { $_.IsChecked -eq $true }).Count -gt 0
    $anyTweaks = @($tweakCheckboxMap.Keys | Where-Object { $_.IsChecked -eq $true }).Count -gt 0
    if (-not $anyApps -and -not $anyTweaks) { Write-Log "Nothing selected (no apps or tweaks)."; return }

    $BtnApply.IsEnabled = $false
    try {
        if ($anyApps)   { Install-SelectedApps }
        if ($anyTweaks) { Apply-SelectedTweaks }
        Write-Log "Done."
    } finally {
        $BtnApply.IsEnabled = $true
    }
})

$BtnUndo.Add_Click({
    $confirm = [System.Windows.MessageBox]::Show(
        "This will undo all actions recorded in the log (uninstall apps installed by STweak and revert tweaks applied by STweak). Continue?",
        "Undo Everything", "YesNo", "Warning")
    if ($confirm -ne "Yes") { return }

    $log = Get-ActionLog

    foreach ($app in @($log.installedApps)) {
        Write-Log "Uninstalling tracked app: $($app.name) ..."
        try {
            Start-Process -FilePath "winget" -ArgumentList "uninstall --id $($app.id) -e --silent --accept-source-agreements" -Wait -NoNewWindow
            Write-Log "Uninstalled $($app.name)."
        } catch {
            Write-Log "FAILED to uninstall $($app.name): $($_.Exception.Message)"
        }
    }

    foreach ($tweakLog in @($log.appliedTweaks)) {
        $tweakDef = $TweakCatalog | Where-Object { $_.Key -eq $tweakLog.key }
        if ($tweakDef -and $tweakDef.Undo) {
            Write-Log "Reverting tweak: $($tweakLog.name) ..."
            try {
                & $tweakDef.Undo
                Write-Log "Reverted tweak: $($tweakLog.name)."
            } catch {
                Write-Log "FAILED to revert tweak $($tweakLog.name): $($_.Exception.Message)"
            }
        }
    }

    if (Test-Path $LogFile) {
        @{ installedApps = @(); appliedTweaks = @() } | ConvertTo-Json | Set-Content -Path $LogFile -Encoding UTF8
    }

    Write-Log "Undo complete. STweak's action log has been cleared."
})

Update-UninstallGrid
$Window.ShowDialog() | Out-Null