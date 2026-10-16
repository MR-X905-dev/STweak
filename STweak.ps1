
#Requires -Version 5.1

param(
    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$LASTEXITCODE = 0

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

if ((-not $ValidateOnly) -and (-not (Test-IsAdmin))) {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or -not (Test-Path -LiteralPath $PSCommandPath)) {
        Write-Host 'STweak must run as Administrator. Save this file as .ps1 and run it, or launch it from an elevated PowerShell window.' -ForegroundColor Red
        Start-Sleep -Seconds 8
        return
    }
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"')
        ) | Out-Null
    } catch {
        Write-Host ('Could not restart with Administrator rights: ' + $_.Exception.Message) -ForegroundColor Red
        Start-Sleep -Seconds 8
    }
    return
}

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic

$RootDir       = Join-Path $env:ProgramData 'STweak'
$LogFile       = Join-Path $RootDir 'actions.json'
$TextLogFile   = Join-Path $RootDir 'stweak.log'
$QuarantineDir = Join-Path $RootDir 'Quarantine'
$ManifestFile  = Join-Path $QuarantineDir 'manifest.json'
$RegBackupDir  = Join-Path $RootDir 'RegBackups'
$TaskBackupDir = Join-Path $RootDir 'TaskBackups'
$BgDir         = Join-Path $RootDir 'Bg'

foreach ($d in @($RootDir, $QuarantineDir, $RegBackupDir, $TaskBackupDir, $BgDir)) {
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

function Write-FileLog {
    param([string]$Text)
    try {
        $line = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + '  ' + $Text
        Add-Content -LiteralPath $TextLogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}

function ConvertTo-HashtableDeep {
    param($obj)
    if ($null -eq $obj) { return @{} }
    if ($obj -is [System.Collections.IDictionary]) { return $obj }
    if ($obj -is [System.Array]) {
        $arr = @()
        foreach ($it in $obj) { $arr += ,(ConvertTo-HashtableDeep $it) }
        return $arr
    }
    if ($obj -is [System.Management.Automation.PSCustomObject]) {
        $h = @{}
        foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = ConvertTo-HashtableDeep $p.Value }
        return $h
    }
    return $obj
}

function Get-NormalizedPath {
    param([string]$p)
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    try { return [System.IO.Path]::GetFullPath($p.Trim().Trim('"')).TrimEnd('\') } catch { return $null }
}

function Test-PathUnder {
    param([string]$Child, [string]$Parent)
    if (-not $Child -or -not $Parent) { return $false }
    return $Child.StartsWith($Parent.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-RegExePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = $Path -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
    $p = $p -replace '^HKCU:', 'HKEY_CURRENT_USER'
    $p = $p -replace '^HKLM:', 'HKEY_LOCAL_MACHINE'
    $p = $p -replace '^HKU:',  'HKEY_USERS'
    $p = $p -replace '^HKCR:', 'HKEY_CLASSES_ROOT'
    return $p
}

function ConvertTo-PSRegPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = $Path.Trim()
    $pfx = 'Microsoft.PowerShell.Core\Registry::'
    if ($p.StartsWith($pfx, [System.StringComparison]::OrdinalIgnoreCase)) { $p = $p.Substring($pfx.Length) }
    $shortMap = @(
        @{ K = 'HKCU\'; V = 'HKCU:\' },
        @{ K = 'HKLM\'; V = 'HKLM:\' },
        @{ K = 'HKU\';  V = 'HKU:\' },
        @{ K = 'HKCR\'; V = 'HKCR:\' },
        @{ K = 'HKCC\'; V = 'HKCC:\' }
    )
    foreach ($e in $shortMap) {
        if ($p.StartsWith($e.K, [System.StringComparison]::OrdinalIgnoreCase)) {
            return ($e.V + $p.Substring($e.K.Length))
        }
    }
    $map = @(
        @{ K = 'HKEY_CURRENT_USER\';   V = 'HKCU:\' },
        @{ K = 'HKEY_LOCAL_MACHINE\';  V = 'HKLM:\' },
        @{ K = 'HKEY_USERS\';          V = 'HKU:\' },
        @{ K = 'HKEY_CLASSES_ROOT\';   V = 'HKCR:\' },
        @{ K = 'HKEY_CURRENT_CONFIG\'; V = 'HKCC:\' }
    )
    foreach ($e in $map) {
        if ($p.StartsWith($e.K, [System.StringComparison]::OrdinalIgnoreCase)) {
            return ($e.V + $p.Substring($e.K.Length))
        }
    }
    return $p
}

function Export-RegKeyBackup {
    param([string]$RegKeyPath)
    $regPath = ConvertTo-RegExePath $RegKeyPath
    if (-not $regPath) { return $null }
    if (-not (Test-Path -LiteralPath $RegBackupDir)) { New-Item -ItemType Directory -Path $RegBackupDir -Force | Out-Null }
    $safe = ($regPath -replace '[\\/:*?"<>|]', '_')
    $file = Join-Path $RegBackupDir ($safe + '_' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.reg')
    try {
        & reg.exe export $regPath $file /y | Out-Null
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $file)) { return $file }
    } catch { }
    return $null
}

function Format-SavedState {
    param($State)
    $h = ConvertTo-HashtableDeep $State
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($k in $h.Keys) {
        $v = $h[$k]
        if ($v -is [System.Collections.IDictionary] -or $v -is [System.Management.Automation.PSCustomObject]) {
            $inner = ConvertTo-HashtableDeep $v
            if ($inner.ContainsKey('Exists')) {
                if ([bool]$inner['Exists']) { [void]$out.Add(("{0} -> restore to '{1}' (type {2})" -f $k, $inner['Value'], $inner['Kind'])) }
                else                       { [void]$out.Add(("{0} -> remove (did not exist before)" -f $k)) }
                continue
            }
        }
        [void]$out.Add(("{0} = {1}" -f $k, $v))
    }
    return $out.ToArray()
}

function Get-VariantNames {
    param([string]$DisplayName, [string]$Publisher = '')
    $stop = @('inc','llc','ltd','corp','corporation','technologies','technology','software','team','foundation','project','community','gmbh','limited','company','solutions','systems','labs','studio','group','the','and','for','co')
    $set = New-Object System.Collections.Generic.List[string]
    $add = {
        param([string]$s)
        if ($s -and $s.Trim().Length -ge 4 -and -not $set.Contains($s)) { [void]$set.Add($s) }
    }.GetNewClosure()
    $base = ($DisplayName -replace '[^\w\s]', ' ').Trim()
    $parts = @($base -split '\s+' | Where-Object { $_ })
    & $add $base
    & $add ($parts -join '')
    if ($parts.Count -ge 1) { & $add $parts[0] }
    if ($parts.Count -ge 2) { & $add ($parts[0] + $parts[1]); & $add ($parts[0] + ' ' + $parts[1]) }
    if ($Publisher) {
        $pubParts = @((($Publisher -replace '[^\w\s]', ' ').Trim()) -split '\s+' | Where-Object { $_ })
        $kept = 0
        foreach ($w in $pubParts) {
            if ($stop -contains $w.ToLower()) { continue }
            & $add $w
            $kept++
            if ($kept -ge 2) { break }
        }
        if ($pubParts.Count -ge 2) { & $add ($pubParts[0] + $pubParts[1]) }
    }
    return $set.ToArray()
}

function Get-RegValueOrNull {
    param([string]$Path, [string]$Name)
    if (Test-Path -LiteralPath $Path) {
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

function Set-RegValueOrRemove {
    param([string]$Path, [string]$Name, $PrevState, [string]$FallbackType)
    $ps = ConvertTo-HashtableDeep $PrevState
    $exists = $false; $value = $null; $kind = $null
    if ($ps.ContainsKey('Exists')) { $exists = [bool]$ps['Exists'] }
    if ($ps.ContainsKey('Value'))  { $value  = $ps['Value'] }
    if ($ps.ContainsKey('Kind'))   { $kind   = $ps['Kind'] }
    if (-not $exists) {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        return
    }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    $type = $FallbackType
    if ($kind -and $kind -ne 'None') { $type = [string]$kind }
    Set-ItemProperty -Path $Path -Name $Name -Value $value -Type $type
}

function New-EmptyActionLog {
    [PSCustomObject]@{ schemaVersion = 2; installedApps = @(); appliedTweaks = @() }
}

function Get-ActionLog {
    foreach ($candidate in @($LogFile, ($LogFile + '.bak'))) {
        if (-not (Test-Path -LiteralPath $candidate)) { continue }
        try {
            $raw = Get-Content -LiteralPath $candidate -Raw -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($raw)) { throw 'file is empty' }
            $obj = $raw | ConvertFrom-Json -ErrorAction Stop
            $names = @($obj.PSObject.Properties.Name)
            if (($names -notcontains 'installedApps') -or ($names -notcontains 'appliedTweaks')) { throw 'unexpected structure' }
            $obj.installedApps = @($obj.installedApps | Where-Object { $_ })
            $obj.appliedTweaks = @($obj.appliedTweaks | Where-Object { $_ })
            if ($candidate -ne $LogFile) { Write-FileLog 'WARNING: main action log was damaged; recovered from the backup copy.' }
            return $obj
        } catch {
            $aside = $candidate + '.corrupt-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
            try { Copy-Item -LiteralPath $candidate -Destination $aside -ErrorAction Stop } catch { }
            Write-FileLog ('WARNING: could not read ' + $candidate + ' (' + $_.Exception.Message + '); corrupt copy kept as ' + $aside)
        }
    }
    return (New-EmptyActionLog)
}

function Save-ActionLog {
    param($log)
    $log | Add-Member -NotePropertyName schemaVersion -NotePropertyValue 2 -Force
    $tmp = $LogFile + '.tmp'
    $json = $log | ConvertTo-Json -Depth 10
    Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8 -ErrorAction Stop
    $null = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json -ErrorAction Stop
    if (Test-Path -LiteralPath $LogFile) {
        [System.IO.File]::Replace($tmp, $LogFile, ($LogFile + '.bak'))
    } else {
        Move-Item -LiteralPath $tmp -Destination $LogFile -Force
    }
}

function Add-InstalledApp {
    param([string]$WingetId, [string]$DisplayName)
    $log = Get-ActionLog
    $list = @($log.installedApps)
    $found = $false
    foreach ($e in $list) { if ($e.id -eq $WingetId) { $found = $true } }
    if (-not $found) {
        $list += [PSCustomObject]@{ id = $WingetId; name = $DisplayName; date = (Get-Date).ToString('s') }
        $log.installedApps = $list
        Save-ActionLog $log
    }
}

function Add-AppliedTweak {
    param([string]$TweakKey, [string]$DisplayName, $State)
    $log = Get-ActionLog
    $list = @($log.appliedTweaks)
    $existing = $null
    foreach ($e in $list) { if ($e.key -eq $TweakKey) { $existing = $e } }
    if ($existing) {
        $existing.date = (Get-Date).ToString('s')
    } else {
        $list += [PSCustomObject]@{ key = $TweakKey; name = $DisplayName; date = (Get-Date).ToString('s'); state = $State }
    }
    $log.appliedTweaks = $list
    Save-ActionLog $log
}

function Merge-AppliedTweakExtraState {
    param([string]$TweakKey, $Extra)
    if (-not $Extra) { return }
    $log = Get-ActionLog
    foreach ($item in $log.appliedTweaks) {
        if ($item.key -eq $TweakKey) {
            $merged = ConvertTo-HashtableDeep $item.state
            $e = ConvertTo-HashtableDeep $Extra
            foreach ($k in $e.Keys) { $merged[$k] = $e[$k] }
            $item.state = $merged
        }
    }
    Save-ActionLog $log
}

function Remove-AppliedTweakEntry {
    param([string]$TweakKey)
    $log = Get-ActionLog
    $log.appliedTweaks = @($log.appliedTweaks | Where-Object { $_.key -ne $TweakKey })
    Save-ActionLog $log
}

function Remove-InstalledAppEntry {
    param([string]$WingetId)
    $log = Get-ActionLog
    $log.installedApps = @($log.installedApps | Where-Object { $_.id -ne $WingetId })
    Save-ActionLog $log
}

function New-RegTweak {
    param(
        [string]$Key, [string]$Name, [string]$Category,
        [array]$Targets, [hashtable]$Flags = @{}
    )
    $er = $false; $so = $false; $note = ''
    if ($Flags.ContainsKey('ExplorerRestart')) { $er = [bool]$Flags['ExplorerRestart'] }
    if ($Flags.ContainsKey('SignOut'))         { $so = [bool]$Flags['SignOut'] }
    if ($Flags.ContainsKey('Note'))            { $note = [string]$Flags['Note'] }
    [PSCustomObject]@{
        Key = $Key; Name = $Name; Category = $Category
        NeedsExplorerRestart = $er
        NeedsSignOut = $so
        Note = $note
        GetState = {
            $state = @{}
            foreach ($t in $Targets) { $state["$($t.Path)|$($t.Name)"] = Get-RegValueOrNull -Path $t.Path -Name $t.Name }
            return $state
        }.GetNewClosure()
        Plan = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            $out = New-Object System.Collections.Generic.List[string]
            foreach ($t in $Targets) {
                $prev = ConvertTo-HashtableDeep $State["$($t.Path)|$($t.Name)"]
                $cur = '<not set>'
                if ($prev.ContainsKey('Exists') -and [bool]$prev['Exists']) { $cur = "$($prev['Value'])" }
                [void]$out.Add(('SET {0}\{1} [{2}]: {3} -> {4}' -f $t.Path, $t.Name, $t.Type, $cur, $t.Value))
            }
            return $out.ToArray()
        }.GetNewClosure()
        Apply = {
            foreach ($t in $Targets) {
                if (-not (Test-Path -LiteralPath $t.Path)) { New-Item -Path $t.Path -Force -ErrorAction Stop | Out-Null }
                Set-ItemProperty -Path $t.Path -Name $t.Name -Value $t.Value -Type $t.Type -ErrorAction Stop
            }
            return $null
        }.GetNewClosure()
        Restore = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            foreach ($t in $Targets) {
                Set-RegValueOrRemove -Path $t.Path -Name $t.Name -PrevState $State["$($t.Path)|$($t.Name)"] -FallbackType $t.Type
            }
        }.GetNewClosure()
        GetStatus = {
            $total = 0; $ok = 0
            foreach ($t in $Targets) {
                $total++
                $cur = Get-RegValueOrNull -Path $t.Path -Name $t.Name
                if ([bool]$cur['Exists'] -and ("$($cur['Value'])" -eq "$($t.Value)")) { $ok++ }
            }
            if ($ok -eq $total) { return 'Applied' }
            if ($ok -eq 0)      { return 'NotApplied' }
            return 'Partial'
        }.GetNewClosure()
    }
}

function New-ServiceTweak {
    param(
        [string]$Key, [string]$Name, [string]$Category,
        [array]$Services, [hashtable]$Flags = @{}
    )
    $desired = 'Disabled'
    $so = $false; $note = ''
    if ($Flags.ContainsKey('StartupType')) { $desired = [string]$Flags['StartupType'] }
    if ($Flags.ContainsKey('SignOut'))     { $so = [bool]$Flags['SignOut'] }
    if ($Flags.ContainsKey('Note'))        { $note = [string]$Flags['Note'] }
    [PSCustomObject]@{
        Key = $Key; Name = $Name; Category = $Category
        NeedsExplorerRestart = $false
        NeedsSignOut = $so
        Note = $note
        GetState = {
            $state = @{}
            foreach ($s in $Services) {
                $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
                if ($svc) { $state[$s] = @{ Found = $true; StartType = $svc.StartType.ToString(); Status = $svc.Status.ToString() } }
                else      { $state[$s] = @{ Found = $false } }
            }
            return $state
        }.GetNewClosure()
        Plan = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            $out = New-Object System.Collections.Generic.List[string]
            foreach ($s in $Services) {
                $prev = ConvertTo-HashtableDeep $State[$s]
                if ($prev.ContainsKey('Found') -and [bool]$prev['Found']) {
                    [void]$out.Add(('SERVICE {0}: StartType={1}, Status={2} -> Stop + StartType={3}' -f $s, $prev['StartType'], $prev['Status'], $desired))
                } else {
                    [void]$out.Add(('SERVICE {0}: not found on this system - skipped' -f $s))
                }
            }
            return $out.ToArray()
        }.GetNewClosure()
        Apply = {
            $failed = New-Object System.Collections.Generic.List[string]
            foreach ($s in $Services) {
                $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
                if (-not $svc) { continue }
                try {
                    if ($svc.Status -ne 'Stopped') { Stop-Service -Name $s -Force -ErrorAction Stop }
                    Set-Service -Name $s -StartupType $desired -ErrorAction Stop
                } catch { [void]$failed.Add(('{0}: {1}' -f $s, $_.Exception.Message)) }
            }
            if ($failed.Count -gt 0) { throw ('Some services could not be changed: ' + ($failed -join '; ')) }
            return $null
        }.GetNewClosure()
        Restore = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            foreach ($s in $Services) {
                $prev = ConvertTo-HashtableDeep $State[$s]
                if (-not ($prev.ContainsKey('Found') -and [bool]$prev['Found'])) { continue }
                try {
                    Set-Service -Name $s -StartupType $prev['StartType'] -ErrorAction SilentlyContinue
                    if ($prev['Status'] -eq 'Running') { Start-Service -Name $s -ErrorAction SilentlyContinue }
                } catch { }
            }
        }.GetNewClosure()
        GetStatus = {
            $total = 0; $ok = 0
            foreach ($s in $Services) {
                $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
                if (-not $svc) { continue }
                $total++
                if ($svc.StartType.ToString() -eq $desired) { $ok++ }
            }
            if ($total -eq 0)    { return 'NotApplicable' }
            if ($ok -eq $total)  { return 'Applied' }
            if ($ok -eq 0)       { return 'NotApplied' }
            return 'Partial'
        }.GetNewClosure()
    }
}

function New-TaskTweak {
    param(
        [string]$Key, [string]$Name, [string]$Category,
        [array]$Tasks, [hashtable]$Flags = @{}
    )
    $note = ''
    if ($Flags.ContainsKey('Note')) { $note = [string]$Flags['Note'] }
    [PSCustomObject]@{
        Key = $Key; Name = $Name; Category = $Category
        NeedsExplorerRestart = $false
        NeedsSignOut = $false
        Note = $note
        GetState = {
            $state = @{}
            foreach ($t in $Tasks) {
                $id = "$($t.Path)|$($t.Name)"
                $task = Get-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -ErrorAction SilentlyContinue
                if ($task) { $state[$id] = @{ Found = $true; Enabled = [bool]$task.Settings.Enabled } }
                else       { $state[$id] = @{ Found = $false } }
            }
            return $state
        }.GetNewClosure()
        Plan = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            $out = New-Object System.Collections.Generic.List[string]
            foreach ($t in $Tasks) {
                $prev = ConvertTo-HashtableDeep $State["$($t.Path)|$($t.Name)"]
                if ($prev.ContainsKey('Found') -and [bool]$prev['Found']) {
                    [void]$out.Add(('TASK {0}{1}: Enabled={2} -> Disabled' -f $t.Path, $t.Name, $prev['Enabled']))
                } else {
                    [void]$out.Add(('TASK {0}{1}: not present on this system - skipped' -f $t.Path, $t.Name))
                }
            }
            return $out.ToArray()
        }.GetNewClosure()
        Apply = {
            foreach ($t in $Tasks) {
                if (Get-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -ErrorAction SilentlyContinue) {
                    Disable-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -ErrorAction Stop | Out-Null
                }
            }
            return $null
        }.GetNewClosure()
        Restore = {
            param($State)
            $State = ConvertTo-HashtableDeep $State
            foreach ($t in $Tasks) {
                $prev = ConvertTo-HashtableDeep $State["$($t.Path)|$($t.Name)"]
                if (-not ($prev.ContainsKey('Found') -and [bool]$prev['Found'])) { continue }
                if ([bool]$prev['Enabled']) {
                    Enable-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }.GetNewClosure()
        GetStatus = {
            $total = 0; $ok = 0
            foreach ($t in $Tasks) {
                $task = Get-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -ErrorAction SilentlyContinue
                if (-not $task) { continue }
                $total++
                if (-not $task.Settings.Enabled) { $ok++ }
            }
            if ($total -eq 0)   { return 'NotApplicable' }
            if ($ok -eq $total) { return 'Applied' }
            if ($ok -eq 0)      { return 'NotApplied' }
            return 'Partial'
        }.GetNewClosure()
    }
}

function New-CmdTweak {
    param(
        [string]$Key, [string]$Name, [string]$Category,
        [scriptblock]$GetState, [scriptblock]$Plan, [scriptblock]$Apply, [scriptblock]$Restore,
        [scriptblock]$GetStatus = $null, [hashtable]$Flags = @{}
    )
    $er = $false; $so = $false; $note = ''
    if ($Flags.ContainsKey('ExplorerRestart')) { $er = [bool]$Flags['ExplorerRestart'] }
    if ($Flags.ContainsKey('SignOut'))         { $so = [bool]$Flags['SignOut'] }
    if ($Flags.ContainsKey('Note'))            { $note = [string]$Flags['Note'] }
    $gs = $GetStatus
    if (-not $gs) { $gs = { return 'Unknown' } }
    [PSCustomObject]@{
        Key = $Key; Name = $Name; Category = $Category
        NeedsExplorerRestart = $er
        NeedsSignOut = $so
        Note = $note
        GetState = $GetState
        Plan     = $Plan
        Apply    = $Apply
        Restore  = $Restore
        GetStatus = $gs
    }
}


$RegTweaks = @(

    @{ K='DisableTelemetry'; N='Disable Telemetry'; C='Privacy'; T=@(
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='AllowTelemetry'; Type='DWord'; Value=0}
        @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; Name='AllowTelemetry'; Type='DWord'; Value=0}
    )}

    @{ K='DisableAdvertisingID'; N='Disable Advertising ID'; C='Privacy'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; Name='Enabled'; Type='DWord'; Value=0}
    )}

    @{ K='DisableTailoredExperiences'; N='Disable Tailored Experiences'; C='Privacy'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy'; Name='TailoredExperiencesWithDiagnosticDataEnabled'; Type='DWord'; Value=0}
    )}

    @{ K='DisableActivityHistory'; N='Disable Activity History'; C='Privacy'; T=@(
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableActivityFeed'; Type='DWord'; Value=0}
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='PublishUserActivities'; Type='DWord'; Value=0}
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='UploadUserActivities'; Type='DWord'; Value=0}
    )}

    @{ K='DisableCortana'; N='Disable Cortana'; C='Privacy'; T=@(
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='AllowCortana'; Type='DWord'; Value=0}
    )}

    @{ K='DisableCopilot'; N='Disable Windows Copilot'; C='Privacy'; T=@(
        @{Path='HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'; Name='TurnOffWindowsCopilot'; Type='DWord'; Value=1}
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'; Name='TurnOffWindowsCopilot'; Type='DWord'; Value=1}
    )}

    @{ K='DisableWebSearchStartMenu'; N='Disable Web Search in Start Menu'; C='Privacy'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'; Name='BingSearchEnabled'; Type='DWord'; Value=0}
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'; Name='CortanaConsent'; Type='DWord'; Value=0}
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='DisableSearchBoxSuggestions'; Type='DWord'; Value=1}
    )}

    @{ K='DisableContentSuggestions'; N='Disable Suggested Apps and Tips'; C='Privacy'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SubscribedContent-338388Enabled'; Type='DWord'; Value=0}
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SubscribedContent-338389Enabled'; Type='DWord'; Value=0}
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SubscribedContent-338393Enabled'; Type='DWord'; Value=0}
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SubscribedContent-310093Enabled'; Type='DWord'; Value=0}
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SystemPaneSuggestionsEnabled'; Type='DWord'; Value=0}
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SilentInstalledAppsEnabled'; Type='DWord'; Value=0}
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SoftLandingEnabled'; Type='DWord'; Value=0}
    )}

    @{ K='DisableLocationTracking'; N='Disable Location Tracking'; C='Privacy'; T=@(
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'; Name='DisableLocation'; Type='DWord'; Value=1}
    )}

    @{ K='DisableFeedbackRequests'; N='Disable Feedback Requests'; C='Privacy'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Siuf\Rules'; Name='NumberOfSIUFInPeriod'; Type='DWord'; Value=0}
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='DoNotShowFeedbackNotifications'; Type='DWord'; Value=1}
    )}

    @{ K='DisableAppLaunchTracking'; N='Disable App Launch Tracking'; C='Privacy'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='Start_TrackProgs'; Type='DWord'; Value=0}
    )}

    @{ K='DisableRecentDocsTracking'; N='Disable Recent Documents Tracking'; C='Privacy'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='Start_TrackDocs'; Type='DWord'; Value=0}
    )}

    @{ K='DisableStoreAutoUpdate'; N='Disable Store Auto-Update'; C='Privacy'; T=@(
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'; Name='AutoDownload'; Type='DWord'; Value=2}
    )}

    @{ K='ShowFileExtensions'; N='Show File Extensions'; C='Explorer'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='HideFileExt'; Type='DWord'; Value=0}
    )}

    @{ K='ShowHiddenFiles'; N='Show Hidden Files'; C='Explorer'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='Hidden'; Type='DWord'; Value=1}
    )}

    @{ K='FasterMenus'; N='Faster Menu Animation'; C='Explorer'; T=@(
        @{Path='HKCU:\Control Panel\Desktop'; Name='MenuShowDelay'; Type='String'; Value='0'}
    )}

    @{ K='ShowSecondsInClock'; N='Show Seconds in Taskbar Clock'; C='Explorer'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='ShowSecondsInSystemClock'; Type='DWord'; Value=1}
    )}

    @{ K='SearchIconOnly'; N='Taskbar Search: Icon Only'; C='Explorer'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='SearchboxTaskbarMode'; Type='DWord'; Value=1}
    )}

    @{ K='HideChatIcon'; N='Hide Taskbar Chat Icon'; C='Explorer'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='TaskbarMn'; Type='DWord'; Value=0}
    )}

    @{ K='DisableWidgets'; N='Disable Widgets / News and Interests'; C='Explorer'; T=@(
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Dsh'; Name='AllowNewsAndInterests'; Type='DWord'; Value=0}
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds'; Name='EnableFeeds'; Type='DWord'; Value=0}
    )}

    @{ K='DisableKeyboardShortcutPrompts'; N='Disable Accessibility Shortcut Prompts (Sticky/Toggle/Filter Keys)'; C='Accessibility'; F=@{Note='Stops the accidental Shift x5 / Shift x8 keyboard prompts.'}; T=@(
        @{Path='HKCU:\Control Panel\Accessibility\StickyKeys'; Name='Flags'; Type='String'; Value='506'}
        @{Path='HKCU:\Control Panel\Accessibility\ToggleKeys'; Name='Flags'; Type='String'; Value='58'}
        @{Path='HKCU:\Control Panel\Accessibility\FilterKeys'; Name='Flags'; Type='String'; Value='122'}
    )}

    @{ K='EnableDarkMode'; N='Enable Dark Mode'; C='Appearance'; F=@{SignOut=$true; Note='Sign out and back in for the full theme change.'}; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'; Name='SystemUsesLightTheme'; Type='DWord'; Value=0}
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'; Name='AppsUseLightTheme'; Type='DWord'; Value=0}
    )}

    @{ K='VisualFXPerformance'; N='Visual Effects: Best Performance'; C='Performance'; F=@{ExplorerRestart=$true}; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'; Name='VisualFXSetting'; Type='DWord'; Value=2}
    )}

    @{ K='DisablePowerThrottling'; N='Disable Power Throttling'; C='Performance'; T=@(
        @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling'; Name='PowerThrottlingOff'; Type='DWord'; Value=1}
    )}

    @{ K='Win32PrioritySeparation'; N='Win32 Priority Separation (foreground boost)'; C='Performance'; T=@(
        @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl'; Name='Win32PrioritySeparation'; Type='DWord'; Value=38}
    )}

    @{ K='DisableGameDVR'; N='Disable Xbox Game Bar / Game DVR Recording'; C='Performance'; T=@(
        @{Path='HKCU:\System\GameConfigStore'; Name='GameDVR_Enabled'; Type='DWord'; Value=0}
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'; Name='AllowGameDVR'; Type='DWord'; Value=0}
    )}

    @{ K='DisableStartupDelay'; N='Disable Startup Delay for Apps'; C='Performance'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize'; Name='StartupDelayInMSec'; Type='DWord'; Value=0}
    )}

    @{ K='EnableLongPaths'; N='Enable NTFS Long Paths (260+ chars)'; C='System'; T=@(
        @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'; Name='LongPathsEnabled'; Type='DWord'; Value=1}
    )}

    @{ K='DisableFastStartup'; N='Disable Fast Startup'; C='System'; T=@(
        @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'; Name='HiberbootEnabled'; Type='DWord'; Value=0}
    )}

    @{ K='DisableDriverAutoUpdate'; N='Disable Automatic Driver Updates via Windows Update'; C='System'; T=@(
        @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching'; Name='SearchOrderConfig'; Type='DWord'; Value=0}
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Name='ExcludeWUDriversInQualityUpdate'; Type='DWord'; Value=1}
    )}

    @{ K='NoAutoRebootWU'; N='Windows Update: No Auto-Reboot While Signed In'; C='System'; T=@(
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name='NoAutoRebootWithLoggedOnUsers'; Type='DWord'; Value=1}
    )}

    @{ K='DisableDeliveryOptimization'; N='Disable Delivery Optimization P2P Sharing'; C='System'; T=@(
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Name='DODownloadMode'; Type='DWord'; Value=0}
    )}

    @{ K='EnableSmartScreen'; N='Enable SmartScreen'; C='Security'; T=@(
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableSmartScreen'; Type='DWord'; Value=1}
    )}

    @{ K='DisableAutoPlay'; N='Disable AutoPlay / AutoRun'; C='Security'; T=@(
        @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'; Name='DisableAutoplay'; Type='DWord'; Value=1}
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoDriveTypeAutoRun'; Type='DWord'; Value=255}
    )}

    @{ K='DisableLLMNR'; N='Disable LLMNR (NetBIOS name resolution over multicast)'; C='Security'; T=@(
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name='EnableMulticast'; Type='DWord'; Value=0}
    )}

    @{ K='DisableWDigestPlainText'; N='Stop WDigest from storing plain-text credentials'; C='Security'; T=@(
        @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name='UseLogonCredential'; Type='DWord'; Value=0}
    )}

    @{ K='DisableRemoteAssistance'; N='Disable Remote Assistance'; C='Security'; T=@(
        @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'; Name='fAllowToGetHelp'; Type='DWord'; Value=0}
    )}
)

$SvcTweaks = @(
    @{ K='DisableTelemetryServices'; N='Disable Telemetry Services (DiagTrack)'; C='Services'; F=@{Note='Disables Connected User Experiences and Telemetry.'}; T=@('DiagTrack','dmwappushservice') }
    @{ K='DisableSysMain'; N='Disable SysMain (Superfetch)'; C='Services'; F=@{Note='Recommended for SSD systems.'}; T=@('SysMain') }
    @{ K='DisableWindowsSearch'; N='Disable Windows Search Indexing'; C='Services'; F=@{Note='File search / indexing stops; the Start menu still opens programs.'}; T=@('WSearch') }
    @{ K='DisablePrintSpooler'; N='Disable Print Spooler'; C='Services'; F=@{Note='Printing will not work until reverted.'}; T=@('Spooler') }
    @{ K='DisableFaxService'; N='Disable Fax Service'; C='Services'; T=@('Fax') }
    @{ K='DisableRemoteRegistry'; N='Disable Remote Registry'; C='Services'; T=@('RemoteRegistry') }
    @{ K='DisableMapsBroker'; N='Disable Downloaded Maps Manager'; C='Services'; T=@('MapsBroker') }
    @{ K='DisableRetailDemo'; N='Disable Retail Demo Service'; C='Services'; T=@('RetailDemo') }
)

$TaskTweaks = @(
    @{ K='DisableCEIPTasks'; N='Disable Customer Experience Improvement Tasks'; C='Tasks'; T=@(
        @{Path='\Microsoft\Windows\Customer Experience Improvement Program\'; Name='Consolidator'}
        @{Path='\Microsoft\Windows\Customer Experience Improvement Program\'; Name='UsbCeip'}
    )}
    @{ K='DisableAppraiserTasks'; N='Disable Compatibility Appraiser Tasks'; C='Tasks'; T=@(
        @{Path='\Microsoft\Windows\Application Experience\'; Name='Microsoft Compatibility Appraiser'}
        @{Path='\Microsoft\Windows\Application Experience\'; Name='ProgramDataUpdater'}
    )}
    @{ K='DisableStartupAppTask'; N='Disable Startup App Scan Task'; C='Tasks'; T=@(
        @{Path='\Microsoft\Windows\Application Experience\'; Name='StartupAppTask'}
    )}
    @{ K='DisableDiskDiagnosticTask'; N='Disable Disk Diagnostic Data Collector'; C='Tasks'; T=@(
        @{Path='\Microsoft\Windows\DiskDiagnostic\'; Name='Microsoft-Windows-DiskDiagnosticDataCollector'}
    )}
    @{ K='DisableFeedbackTasks'; N='Disable Feedback (Siuf) Tasks'; C='Tasks'; T=@(
        @{Path='\Microsoft\Windows\Feedback\Siuf\'; Name='DmClient'}
        @{Path='\Microsoft\Windows\Feedback\Siuf\'; Name='DmClientOnScenarioDownload'}
    )}
    @{ K='DisableWerQueueReporting'; N='Disable Windows Error Reporting Queue'; C='Tasks'; T=@(
        @{Path='\Microsoft\Windows\Windows Error Reporting\'; Name='QueueReporting'}
    )}
)

$TweakCatalog = New-Object System.Collections.Generic.List[object]

foreach ($e in $RegTweaks) {
    $flags = @{}
    if ($e.ContainsKey('F')) { $flags = $e.F }
    [void]$TweakCatalog.Add((New-RegTweak -Key $e.K -Name $e.N -Category $e.C -Targets $e.T -Flags $flags))
}
foreach ($e in $SvcTweaks) {
    $flags = @{}
    if ($e.ContainsKey('F')) { $flags = $e.F }
    [void]$TweakCatalog.Add((New-ServiceTweak -Key $e.K -Name $e.N -Category $e.C -Services $e.T -Flags $flags))
}
foreach ($e in $TaskTweaks) {
    $flags = @{}
    if ($e.ContainsKey('F')) { $flags = $e.F }
    [void]$TweakCatalog.Add((New-TaskTweak -Key $e.K -Name $e.N -Category $e.C -Tasks $e.T -Flags $flags))
}


$p = @{
    Key = 'DisableHibernation'; Name = 'Disable Hibernation (removes hiberfil.sys)'; Category = 'Power'
    Flags = @{ Note = 'Frees disk space; Fast Startup is affected while hibernation is off.' }
    GetState = {
        $exists = Test-Path -LiteralPath (Join-Path $env:SystemDrive 'hiberfil.sys')
        return @{ HiberfilExists = [bool]$exists }
    }
    Plan = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        if ([bool]$s['HiberfilExists']) { return @('HIBERNATION: on -> off (deletes hiberfil.sys)') }
        return @('HIBERNATION: already off')
    }
    Apply = {
        & powercfg.exe /hibernate off | Out-Null
        return $null
    }
    Restore = {
        & powercfg.exe /hibernate on | Out-Null
    }
    GetStatus = {
        if (Test-Path -LiteralPath (Join-Path $env:SystemDrive 'hiberfil.sys')) { return 'NotApplied' }
        return 'Applied'
    }
}
[void]$TweakCatalog.Add((New-CmdTweak @p))

$p = @{
    Key = 'UltimatePerformancePlan'; Name = 'Ultimate Performance Power Plan'; Category = 'Power'
    GetState = {
        $out = (& powercfg.exe /getactivescheme | Out-String)
        $m = [regex]::Match($out, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')
        $g = ''
        if ($m.Success) { $g = $m.Groups[1].Value }
        return @{ PrevScheme = $g }
    }
    Plan = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        return @(('POWER PLAN: activate "Ultimate Performance" (current scheme: {0})' -f $s['PrevScheme']))
    }
    Apply = {
        $out = (& powercfg.exe /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 2>&1 | Out-String)
        $m = [regex]::Match($out, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')
        if (-not $m.Success) { throw 'Could not create the Ultimate Performance power plan on this system.' }
        $g = $m.Groups[1].Value
        & powercfg.exe /setactive $g | Out-Null
        return @{ CreatedGuid = $g }
    }
    Restore = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        if ($s.ContainsKey('PrevScheme') -and $s['PrevScheme']) { & powercfg.exe /setactive $s['PrevScheme'] | Out-Null }
        if ($s.ContainsKey('CreatedGuid') -and $s['CreatedGuid']) { & powercfg.exe /delete $s['CreatedGuid'] | Out-Null }
    }
    GetStatus = {
        $out = (& powercfg.exe /getactivescheme | Out-String)
        if ($out -match 'Ultimate Performance') { return 'Applied' }
        return 'NotApplied'
    }
}
[void]$TweakCatalog.Add((New-CmdTweak @p))

$p = @{
    Key = 'ClassicRightClickMenu'; Name = 'Classic Windows 10 Right-Click Menu'; Category = 'Explorer'
    Flags = @{ ExplorerRestart = $true; Note = 'Restores the old full context menu in File Explorer.' }
    GetState = {
        $root = 'HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}'
        $key  = $root + '\InprocServer32'
        $rootExists = Test-Path -LiteralPath $root
        $serverExists = Test-Path -LiteralPath $key
        $serverValue = $null
        if ($serverExists) { $serverValue = (Get-RegValueOrNull -Path $key -Name '')['Value'] }
        return @{ RootExists = [bool]$rootExists; ServerExists = [bool]$serverExists; ServerValue = $serverValue }
    }
    Plan = {
        param($State)
        return @('REG: create CLSID {86ca1aa0-...}\InprocServer32 with empty default value (classic context menu)')
    }
    Apply = {
        $key = 'HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'
        if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
        $regKey = Get-Item -LiteralPath $key
        $regKey.SetValue('', '', [Microsoft.Win32.RegistryValueKind]::String)
        return $null
    }
    Restore = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        $root = 'HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}'
        $key  = $root + '\InprocServer32'
        if ([bool]$s['RootExists']) {
            if ([bool]$s['ServerExists']) {
                if (Test-Path -LiteralPath $key) {
                    $regKey = Get-Item -LiteralPath $key
                    $regKey.SetValue('', [string]$s['ServerValue'], [Microsoft.Win32.RegistryValueKind]::String)
                }
            } else {
                if (Test-Path -LiteralPath $key) { Remove-Item -LiteralPath $key -Recurse -Force }
            }
        } else {
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
        }
    }
    GetStatus = {
        $key = 'HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'
        $st = Get-RegValueOrNull -Path $key -Name ''
        if ([bool]$st['Exists']) { return 'Applied' }
        return 'NotApplied'
    }
}
[void]$TweakCatalog.Add((New-CmdTweak @p))

$p = @{
    Key = 'EnablePUAProtection'; Name = 'Defender: Block Potentially Unwanted Apps'; Category = 'Security'
    GetState = {
        try { $v = [int](Get-MpPreference).PUAProtection } catch { $v = -1 }
        return @{ PUA = $v }
    }
    Plan = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        return @(('DEFENDER: PUA protection = {0} -> Enabled' -f $s['PUA']))
    }
    Apply = {
        Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
        return $null
    }
    Restore = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        $v = [int]$s['PUA']
        if ($v -eq 2) { Set-MpPreference -PUAProtection AuditMode -ErrorAction SilentlyContinue }
        else          { Set-MpPreference -PUAProtection Disabled -ErrorAction SilentlyContinue }
    }
    GetStatus = {
        try { $v = [int](Get-MpPreference).PUAProtection } catch { return 'Unknown' }
        if ($v -eq 0) { return 'NotApplied' }
        return 'Applied'
    }
}
[void]$TweakCatalog.Add((New-CmdTweak @p))

$p = @{
    Key = 'DisableSMB1'; Name = 'Disable SMBv1 Server Protocol'; Category = 'Security'
    GetState = {
        try { $c = Get-SmbServerConfiguration } catch { return @{ SMB1 = $null } }
        return @{ SMB1 = [bool]$c.EnableSMB1Protocol }
    }
    Plan = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        return @(('SMB1 server protocol: {0} -> disabled' -f $s['SMB1']))
    }
    Apply = {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
        return $null
    }
    Restore = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        if ($s['SMB1'] -eq $true) { Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction SilentlyContinue }
    }
    GetStatus = {
        try { $c = Get-SmbServerConfiguration } catch { return 'Unknown' }
        if ($c.EnableSMB1Protocol) { return 'NotApplied' }
        return 'Applied'
    }
}
[void]$TweakCatalog.Add((New-CmdTweak @p))

$p = @{
    Key = 'EnsureFirewallOn'; Name = 'Ensure Windows Firewall is ON (all profiles)'; Category = 'Security'
    GetState = {
        $st = @{}
        try { foreach ($prof in (Get-NetFirewallProfile)) { $st[$prof.Name] = [bool]$prof.Enabled } } catch { }
        return $st
    }
    Plan = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        $out = New-Object System.Collections.Generic.List[string]
        foreach ($k in $s.Keys) { [void]$out.Add(('FIREWALL {0}: {1} -> on' -f $k, $s[$k])) }
        return $out.ToArray()
    }
    Apply = {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop
        return $null
    }
    Restore = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        foreach ($k in @('Domain','Private','Public')) {
            if ($s.ContainsKey($k) -and (-not [bool]$s[$k])) {
                Set-NetFirewallProfile -Profile $k -Enabled False -ErrorAction SilentlyContinue
            }
        }
    }
    GetStatus = {
        $all = $true
        $any = $false
        try { $profs = Get-NetFirewallProfile } catch { return 'Unknown' }
        foreach ($prof in $profs) {
            if ($prof.Enabled) { $any = $true } else { $all = $false }
        }
        if ($all) { return 'Applied' }
        if ($any) { return 'Partial' }
        return 'NotApplied'
    }
}
[void]$TweakCatalog.Add((New-CmdTweak @p))

$p = @{
    Key = 'EnableControlledFolderAccess'; Name = 'Defender: Controlled Folder Access (anti-ransomware)'; Category = 'Security'
    Flags = @{ Note = 'Blocks unauthorized apps from writing to Documents, Pictures and Desktop. Some apps may need to be allowed.' }
    GetState = {
        try { $v = [int](Get-MpPreference).EnableControlledFolderAccess } catch { $v = -1 }
        return @{ CFA = $v }
    }
    Plan = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        return @(('DEFENDER: Controlled Folder Access = {0} -> Enabled' -f $s['CFA']))
    }
    Apply = {
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop
        return $null
    }
    Restore = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        $v = [int]$s['CFA']
        if ($v -eq 2) { Set-MpPreference -EnableControlledFolderAccess AuditMode -ErrorAction SilentlyContinue }
        else          { Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue }
    }
    GetStatus = {
        try { $v = [int](Get-MpPreference).EnableControlledFolderAccess } catch { return 'Unknown' }
        if ($v -eq 0) { return 'NotApplied' }
        return 'Applied'
    }
}
[void]$TweakCatalog.Add((New-CmdTweak @p))

$p = @{
    Key = 'DisableGuestAccount'; Name = 'Disable Built-in Guest Account'; Category = 'Security'
    GetState = {
        $g = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($g) { return @{ Found = $true; Enabled = [bool]$g.Enabled } }
        return @{ Found = $false; Enabled = $false }
    }
    Plan = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        if ([bool]$s['Found']) { return @(('LOCAL USER Guest: Enabled={0} -> disabled' -f $s['Enabled'])) }
        return @('LOCAL USER Guest: not present on this system')
    }
    Apply = {
        $g = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($g) { Disable-LocalUser -Name 'Guest' -ErrorAction Stop }
        return $null
    }
    Restore = {
        param($State)
        $s = ConvertTo-HashtableDeep $State
        if ([bool]$s['Found'] -and [bool]$s['Enabled']) { Enable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue }
    }
    GetStatus = {
        $g = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if (-not $g) { return 'NotApplicable' }
        if ($g.Enabled) { return 'NotApplied' }
        return 'Applied'
    }
}
[void]$TweakCatalog.Add((New-CmdTweak @p))

$TweakByKey = @{}
foreach ($t in $TweakCatalog) { $TweakByKey[$t.Key] = $t }

$Presets = @{
    'Safe Starter' = @(
        'DisableTelemetry','DisableAdvertisingID','ShowFileExtensions','EnableSmartScreen','DisableAutoPlay',
        'DisableLLMNR','DisableRemoteAssistance','EnablePUAProtection','EnsureFirewallOn','DisableTelemetryServices','DisableCEIPTasks'
    )
    'Privacy Max' = @(
        'DisableTelemetry','DisableAdvertisingID','DisableTailoredExperiences','DisableActivityHistory','DisableCortana',
        'DisableCopilot','DisableWebSearchStartMenu','DisableContentSuggestions','DisableLocationTracking','DisableFeedbackRequests',
        'DisableAppLaunchTracking','DisableRecentDocsTracking','DisableStoreAutoUpdate','DisableTelemetryServices','DisableCEIPTasks',
        'DisableAppraiserTasks','DisableFeedbackTasks','DisableWerQueueReporting','DisableWDigestPlainText','DisableLLMNR'
    )
    'Performance' = @(
        'DisableTelemetry','DisablePowerThrottling','Win32PrioritySeparation','DisableGameDVR','VisualFXPerformance',
        'DisableStartupDelay','DisableSysMain','DisableFastStartup','UltimatePerformancePlan','DisableHibernation'
    )
    'Developer' = @(
        'ShowFileExtensions','ShowHiddenFiles','EnableLongPaths','ClassicRightClickMenu','EnableDarkMode',
        'ShowSecondsInClock','FasterMenus','DisableSMB1','DisableDriverAutoUpdate','NoAutoRebootWU'
    )
}

foreach ($pn in $Presets.Keys) {
    foreach ($tk in $Presets[$pn]) {
        if (-not $TweakByKey.ContainsKey($tk)) { throw ('Preset "' + $pn + '" references unknown tweak "' + $tk + '".') }
    }
}


function App {
    param([string]$Name, [string]$Id, [string]$Category)
    [PSCustomObject]@{ Name = $Name; Id = $Id; Category = $Category }
}

$AppCatalog = @(

    (App 'Google Chrome' 'Google.Chrome' 'Browsers')
    (App 'Mozilla Firefox' 'Mozilla.Firefox' 'Browsers')
    (App 'Firefox ESR' 'Mozilla.Firefox.ESR' 'Browsers')
    (App 'Brave' 'Brave.Brave' 'Browsers')
    (App 'Opera' 'Opera.Opera' 'Browsers')
    (App 'Vivaldi' 'Vivaldi.Vivaldi' 'Browsers')
    (App 'Tor Browser' 'TorProject.TorBrowser' 'Browsers')

    (App 'Visual C++ Redistributable 2015+ (x64)' 'Microsoft.VCRedist.2015+.x64' 'Runtimes & Libraries')
    (App 'Visual C++ Redistributable 2015+ (x86)' 'Microsoft.VCRedist.2015+.x86' 'Runtimes & Libraries')
    (App '.NET Desktop Runtime 8' 'Microsoft.DotNet.DesktopRuntime.8' 'Runtimes & Libraries')
    (App '.NET Desktop Runtime 9' 'Microsoft.DotNet.DesktopRuntime.9' 'Runtimes & Libraries')
    (App 'ASP.NET Core Runtime 8' 'Microsoft.DotNet.AspNetCore.8' 'Runtimes & Libraries')
    (App 'Temurin Java JRE 8' 'EclipseAdoptium.Temurin.8.JRE' 'Runtimes & Libraries')
    (App 'Temurin Java JRE 17' 'EclipseAdoptium.Temurin.17.JRE' 'Runtimes & Libraries')
    (App 'Temurin Java JDK 21' 'EclipseAdoptium.Temurin.21.JDK' 'Runtimes & Libraries')
    (App 'WebView2 Runtime' 'Microsoft.EdgeWebView2Runtime' 'Runtimes & Libraries')
    (App 'DirectX End-User Runtime' 'Microsoft.DirectX' 'Runtimes & Libraries')

    (App 'Visual Studio Code' 'Microsoft.VisualStudioCode' 'Development')
    (App 'VS Code Insiders' 'Microsoft.VisualStudioCode.Insiders' 'Development')
    (App 'Visual Studio 2022 Community' 'Microsoft.VisualStudio.2022.Community' 'Development')
    (App 'Visual Studio 2022 Professional' 'Microsoft.VisualStudio.2022.Professional' 'Development')
    (App 'Visual Studio Build Tools 2022' 'Microsoft.VisualStudio.2022.BuildTools' 'Development')
    (App 'Git' 'Git.Git' 'Development')
    (App 'GitHub Desktop' 'GitHub.GitHubDesktop' 'Development')
    (App 'Git LFS' 'GitHub.GitLFS' 'Development')
    (App 'TortoiseGit' 'TortoiseGit.TortoiseGit' 'Development')
    (App 'Node.js LTS' 'OpenJS.NodeJS.LTS' 'Development')
    (App 'Node.js (Current)' 'OpenJS.NodeJS' 'Development')
    (App 'Python 3.12' 'Python.Python.3.12' 'Development')
    (App 'Anaconda' 'Anaconda.Anaconda3' 'Development')
    (App 'Miniconda' 'Anaconda.Miniconda3' 'Development')
    (App 'IntelliJ IDEA Community' 'JetBrains.IntelliJIDEA.Community' 'Development')
    (App 'PyCharm Community' 'JetBrains.PyCharm.Community' 'Development')
    (App 'WebStorm' 'JetBrains.WebStorm' 'Development')
    (App 'Windows Terminal' 'Microsoft.WindowsTerminal' 'Development')
    (App 'PowerShell 7' 'Microsoft.PowerShell' 'Development')
    (App '.NET SDK 8' 'Microsoft.DotNet.SDK.8' 'Development')
    (App '.NET SDK 9' 'Microsoft.DotNet.SDK.9' 'Development')
    (App 'CMake' 'Kitware.CMake' 'Development')
    (App 'Docker Desktop' 'Docker.DockerDesktop' 'Development')
    (App 'Postman' 'Postman.Postman' 'Development')
    (App 'Insomnia' 'Insomnia.Insomnia' 'Development')
    (App 'DBeaver Community' 'dbeaver.dbeaver' 'Development')
    (App 'HeidiSQL' 'HeidiSQL.HeidiSQL' 'Development')
    (App 'Sourcetree' 'Atlassian.Sourcetree' 'Development')
    (App 'WinMerge' 'WinMerge.WinMerge' 'Development')
    (App 'Notepad++' 'Notepad++.Notepad++' 'Development')
    (App 'Sublime Text 4' 'SublimeHQ.SublimeText.4' 'Development')
    (App 'Rustup' 'Rustlang.Rustup' 'Development')
    (App 'Go' 'GoLang.Go' 'Development')
    (App 'Strawberry Perl' 'StrawberryPerl.StrawberryPerl' 'Development')
    (App 'R for Windows' 'RProject.R' 'Development')
    (App 'RStudio' 'Posit.RStudio' 'Development')
    (App 'AutoHotkey' 'AutoHotkey.AutoHotkey' 'Development')
    (App 'Sysinternals Suite' 'Microsoft.Sysinternals.Suite' 'Development')
    (App 'Process Explorer' 'Microsoft.Sysinternals.ProcessExplorer' 'Development')
    (App 'Process Monitor' 'Microsoft.Sysinternals.ProcessMonitor' 'Development')

    (App 'VLC' 'VideoLAN.VLC' 'Media')
    (App 'MPC-HC' 'clsid2.mpc-hc' 'Media')
    (App 'K-Lite Codec Pack Standard' 'CodecGuide.K-LiteCodecPack.Standard' 'Media')
    (App 'K-Lite Codec Pack Full' 'CodecGuide.K-LiteCodecPack.Full' 'Media')
    (App 'OBS Studio' 'OBSProject.OBSStudio' 'Media')
    (App 'Audacity' 'Audacity.Audacity' 'Media')
    (App 'HandBrake' 'HandBrake.HandBrake' 'Media')
    (App 'Shotcut' 'Meltytech.Shotcut' 'Media')
    (App 'Kdenlive' 'KDE.Kdenlive' 'Media')
    (App 'GIMP' 'GIMP.GIMP' 'Media')
    (App 'Inkscape' 'Inkscape.Inkscape' 'Media')
    (App 'Krita' 'KDE.Krita' 'Media')
    (App 'Blender' 'BlenderFoundation.Blender' 'Media')
    (App 'Spotify' 'Spotify.Spotify' 'Media')
    (App 'MusicBee' 'MusicBee.MusicBee' 'Media')
    (App 'foobar2000' 'PeterPawlowski.foobar2000' 'Media')
    (App 'Adobe Acrobat Reader' 'Adobe.Acrobat.Reader.64-bit' 'Media')
    (App 'IrfanView' 'IrfanView.IrfanView' 'Media')
    (App 'ShareX' 'ShareX.ShareX' 'Media')
    (App 'Greenshot' 'Greenshot.Greenshot' 'Media')
    (App 'Paint.NET' 'dotPDN.PaintDotNet' 'Media')
    (App 'SumatraPDF' 'SumatraPDF.SumatraPDF' 'Media')

    (App 'Discord' 'Discord.Discord' 'Communication')
    (App 'Slack' 'SlackTechnologies.Slack' 'Communication')
    (App 'Zoom' 'Zoom.Zoom' 'Communication')
    (App 'Microsoft Teams' 'Microsoft.Teams' 'Communication')
    (App 'Telegram' 'Telegram.TelegramDesktop' 'Communication')
    (App 'WhatsApp' 'WhatsApp.WhatsApp' 'Communication')
    (App 'Signal' 'OpenWhisperSystems.Signal' 'Communication')
    (App 'Mozilla Thunderbird' 'Mozilla.Thunderbird' 'Communication')
    (App 'Element' 'Element.Element' 'Communication')
    (App 'Skype' 'Microsoft.Skype' 'Communication')
    (App 'KDE Connect' 'KDE.KDEConnect' 'Communication')

    (App 'LibreOffice' 'TheDocumentFoundation.LibreOffice' 'Documents')
    (App 'OnlyOffice Desktop Editors' 'ONLYOFFICE.DesktopEditors' 'Documents')
    (App 'PDF24 Creator' 'geeksoftwareGmbH.PDF24Creator' 'Documents')
    (App 'OpenOffice' 'Apache.OpenOffice' 'Documents')

    (App '7-Zip' '7zip.7zip' 'Utilities')
    (App 'WinRAR' 'RARLab.WinRAR' 'Utilities')
    (App 'PeaZip' 'GiorgioTani.PeaZip' 'Utilities')
    (App 'Rufus' 'Rufus.Rufus' 'Utilities')
    (App 'Ventoy' 'Ventoy.Ventoy' 'Utilities')
    (App 'balenaEtcher' 'Balena.Etcher' 'Utilities')
    (App 'CPU-Z' 'CPUID.CPU-Z' 'Utilities')
    (App 'GPU-Z' 'TechPowerUp.GPU-Z' 'Utilities')
    (App 'HWiNFO' 'REALiX.HWiNFO' 'Utilities')
    (App 'HWMonitor' 'CPUID.HWMonitor' 'Utilities')
    (App 'CrystalDiskInfo' 'CrystalDewWorld.CrystalDiskInfo' 'Utilities')
    (App 'CrystalDiskMark' 'CrystalDewWorld.CrystalDiskMark' 'Utilities')
    (App 'MSI Afterburner' 'Guru3D.Afterburner' 'Utilities')
    (App 'AIDA64 Extreme' 'FinalWire.AIDA64.Extreme' 'Utilities')
    (App 'CCleaner' 'Piriform.CCleaner' 'Utilities')
    (App 'Recuva' 'Piriform.Recuva' 'Utilities')
    (App 'WizTree' 'AntibodySoftware.WizTree' 'Utilities')
    (App 'TreeSize Free' 'JAMSoftware.TreeSize.Free' 'Utilities')
    (App 'WinDirStat' 'WinDirStat.WinDirStat' 'Utilities')
    (App 'Everything (file search)' 'voidtools.Everything' 'Utilities')
    (App 'PowerToys' 'Microsoft.PowerToys' 'Utilities')
    (App 'TranslucentTB' 'TranslucentTB.TranslucentTB' 'Utilities')
    (App 'Files (File Manager)' 'FilesCommunity.Files' 'Utilities')
    (App 'Open-Shell' 'Open-Shell.Open-Shell' 'Utilities')
    (App 'ExplorerPatcher' 'valinet.ExplorerPatcher' 'Utilities')

    (App 'MobaXterm' 'Mobatek.MobaXterm' 'Networking')
    (App 'PuTTY' 'PuTTY.PuTTY' 'Networking')
    (App 'FileZilla' 'TimKosse.FileZilla.Client' 'Networking')
    (App 'WinSCP' 'WinSCP.WinSCP' 'Networking')
    (App 'RustDesk' 'RustDesk.RustDesk' 'Networking')
    (App 'TeamViewer' 'TeamViewer.TeamViewer' 'Networking')
    (App 'AnyDesk' 'AnyDeskSoftwareGmbH.AnyDesk' 'Networking')
    (App 'VNC Viewer' 'RealVNC.VNCViewer' 'Networking')
    (App 'Tailscale' 'tailscale.tailscale' 'Networking')
    (App 'WireGuard' 'WireGuard.WireGuard' 'Networking')

    (App 'Wireshark' 'WiresharkFoundation.Wireshark' 'Security')
    (App 'Nmap' 'Insecure.Nmap' 'Security')
    (App 'Bitwarden' 'Bitwarden.Bitwarden' 'Security')
    (App 'KeePassXC' 'KeePassXCTeam.KeePassXC' 'Security')
    (App 'VeraCrypt' 'IDRIX.VeraCrypt' 'Security')
    (App '1Password' 'AgileBits.1Password' 'Security')

    (App 'Steam' 'Valve.Steam' 'Gaming')
    (App 'Epic Games Launcher' 'EpicGames.EpicGamesLauncher' 'Gaming')
    (App 'EA App' 'ElectronicArts.EADesktop' 'Gaming')
    (App 'Ubisoft Connect' 'Ubisoft.Connect' 'Gaming')
    (App 'Battle.net' 'Blizzard.BattleNet' 'Gaming')
    (App 'GOG Galaxy' 'GOG.Galaxy' 'Gaming')
    (App 'Prism Launcher (Minecraft)' 'PrismLauncher.PrismLauncher' 'Gaming')
)


function Start-BgOperation {
    param(
        [string]$Kind,
        [string]$Title,
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [object]$Payload = $null,
        [scriptblock]$OnDone = $null
    )
    if ($script:BgJob) {
        [System.Windows.MessageBox]::Show('Another background operation is still running. Wait for it to finish.', 'STweak', 'OK', 'Warning') | Out-Null
        return $false
    }
    $log = Join-Path $BgDir ($Kind + '_' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
    $jsonPath = $log + '.json'
    if (Test-Path -LiteralPath $jsonPath) { Remove-Item -LiteralPath $jsonPath -Force -ErrorAction SilentlyContinue }

    $header = 'param($Ctx)' + [Environment]::NewLine +
              '$Payload = $Ctx[''Payload'']' + [Environment]::NewLine +
              '$log = $Ctx[''Log'']' + [Environment]::NewLine +
              '$ErrorActionPreference = ''Stop''' + [Environment]::NewLine +
              'function W($m){ try { Add-Content -LiteralPath $log -Value ((Get-Date).ToString(''HH:mm:ss'') + ''  '' + [string]$m) -Encoding UTF8 -ErrorAction SilentlyContinue } catch { } }' + [Environment]::NewLine

    $text = $header + $Body.ToString()
    $sb = [scriptblock]::Create($text)

    try {
        $ctx = @{ Payload = $Payload; Log = $log }
        $script:BgJob = Start-Job -Name ('STweak_' + $Kind) -ScriptBlock $sb -ArgumentList $ctx
    } catch {
        Write-Log ('Could not start background job: ' + $_.Exception.Message)
        return $false
    }

    $script:BgKind = $Kind
    $script:BgTitle = $Title
    $script:BgLog = $log
    $script:BgJson = $jsonPath
    $script:BgOnDone = $OnDone
    $script:BgStart = Get-Date

    if ($script:TxtBgLog) { $script:TxtBgLog.Text = '' }
    if ($script:TxtBgState) { $script:TxtBgState.Text = $Title }
    if ($script:TxtBgElapsed) { $script:TxtBgElapsed.Text = '00:00' }

    Set-Busy $true
    try { $script:BgTimer.Start() } catch { }
    Write-Log ('Started: ' + $Title)
    return $true
}

function Read-BgResult {
    $res = [PSCustomObject]@{
        Kind   = $script:BgKind
        State  = 'Unknown'
        Error  = $null
        Data   = $null
        Output = @()
    }
    if (-not $script:BgJob) { return $res }
    try { $res.State = $script:BgJob.State.ToString() } catch { $res.State = 'Unknown' }
    try {
        $out = @(Receive-Job -Job $script:BgJob -ErrorAction SilentlyContinue 2>&1)
        $res.Output = @($out | ForEach-Object { [string]$_ })
    } catch { }
    if ($res.State -eq 'Failed') {
        try {
            $reason = $script:BgJob.ChildJobs[0].JobStateInfo.Reason
            if ($reason) { $res.Error = [string]$reason.Message } else { $res.Error = 'The operation failed (see log).' }
        } catch { $res.Error = 'The operation failed (see log).' }
    }
    if ($script:BgJson -and (Test-Path -LiteralPath $script:BgJson)) {
        try {
            $raw = Get-Content -LiteralPath $script:BgJson -Raw -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $res.Data = ConvertTo-HashtableDeep ($raw | ConvertFrom-Json -ErrorAction Stop)
            }
        } catch {
            Write-FileLog ('WARNING: could not read result file ' + $script:BgJson + ' (' + $_.Exception.Message + ')')
        }
    }
    return $res
}

function Clear-BgOperation {
    if ($script:TxtBgState -and $script:BgTitle) {
        $st = ''
        if ($script:BgJob) { try { $st = '  [' + $script:BgJob.State.ToString() + ']' } catch { } }
        $script:TxtBgState.Text = $script:BgTitle + $st
    }
    if ($script:BgJob) {
        try { Remove-Job -Job $script:BgJob -Force -ErrorAction SilentlyContinue } catch { }
    }
    $script:BgJob = $null
    $script:BgOnDone = $null
    Set-Busy $false
}

function Update-BgTick {
    if (-not $script:BgJob) {
        try { $script:BgTimer.Stop() } catch { }
        return
    }
    if ($script:BgLog -and (Test-Path -LiteralPath $script:BgLog)) {
        try {
            $tail = @(Get-Content -LiteralPath $script:BgLog -Tail 300 -ErrorAction SilentlyContinue)
            if ($script:TxtBgLog) {
                $script:TxtBgLog.Text = ($tail -join [Environment]::NewLine)
                $script:TxtBgLog.ScrollToEnd()
            }
        } catch { }
    }
    if ($script:TxtBgElapsed -and $script:BgStart) {
        $el = (Get-Date) - $script:BgStart
        if ($el.TotalHours -ge 1) { $script:TxtBgElapsed.Text = ('{0:h\:mm\:ss}' -f $el) }
        else                      { $script:TxtBgElapsed.Text = ('{0:mm\:ss}' -f $el) }
    }
    if ($script:TxtBgState) {
        try {
            $line = $script:BgTitle + '  ...  ' + $script:BgJob.State.ToString()
            if ($script:TxtBgState.Text -ne $line) { $script:TxtBgState.Text = $line }
        } catch { }
    }
    if ($script:BgJob.State -eq 'Running') { return }

    try { $script:BgTimer.Stop() } catch { }
    $result = Read-BgResult
    $title = $script:BgTitle
    $done = $script:BgOnDone
    Clear-BgOperation
    if ($result.State -eq 'Completed') { Write-Log ('Finished: ' + $title) }
    else { Write-Log ('Finished with state ' + $result.State + ': ' + $title + '  ' + [string]$result.Error) }
    if ($done) {
        try { & $done $result }
        catch { Write-Log ('Completion handler error: ' + $_.Exception.Message) }
    }
}

$script:BgJob = $null
$script:BgKind = ''
$script:BgTitle = ''
$script:BgLog = ''
$script:BgJson = ''
$script:BgOnDone = $null
$script:BgStart = $null

$script:BgTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:BgTimer.Interval = [TimeSpan]::FromMilliseconds(500)
$script:BgTimer.Add_Tick({ Update-BgTick })


$WorkerSrc = @'

$script:WorkerProcPaths = @()
$script:WorkerProcPathsTime = $null

$ProtectedFolderNames = @(
    'microsoft','windows','windowsapps','windowspowershell','windows nt','windows defender',
    'internet explorer','common files','packages','wow6432node','microsoft.net','dotnet',
    '$recycle.bin','system volume information','onedrive','appdata','application data',
    'local','roaming','temp','tmp','programs','public','default','default user','all users',
    'nvidia corporation','amd','intel','edge','edgeupdate','edgewebview'
)

function ConvertTo-NameKey {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return '' }
    return ($s.ToLower() -replace '[^a-z0-9]', '')
}

function Get-NormalizedPath {
    param([string]$p)
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    try { return [System.IO.Path]::GetFullPath($p.Trim().Trim('"')).TrimEnd('\') } catch { return $null }
}

function Test-PathUnder {
    param([string]$Child, [string]$Parent)
    if (-not $Child -or -not $Parent) { return $false }
    $c = $Child.TrimEnd('\')
    $p = $Parent.TrimEnd('\')
    if ($c.Equals($p, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $c.StartsWith($p + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-VariantNames {
    param([string]$DisplayName, [string]$Publisher = '')
    $stop = @('inc','llc','ltd','corp','corporation','technologies','technology','software','team','foundation','project','community','gmbh','limited','company','solutions','systems','labs','studio','group','the','and','for','co')
    $set = New-Object System.Collections.Generic.List[string]
    $add = {
        param([string]$s)
        if ($s -and $s.Trim().Length -ge 4 -and -not $set.Contains($s)) { [void]$set.Add($s) }
    }.GetNewClosure()
    $base = ($DisplayName -replace '[^\w\s]', ' ').Trim()
    $parts = @($base -split '\s+' | Where-Object { $_ })
    & $add $base
    & $add ($parts -join '')
    if ($parts.Count -ge 1) { & $add $parts[0] }
    if ($parts.Count -ge 2) { & $add ($parts[0] + $parts[1]); & $add ($parts[0] + ' ' + $parts[1]) }
    if ($Publisher) {
        $pubParts = @((($Publisher -replace '[^\w\s]', ' ').Trim()) -split '\s+' | Where-Object { $_ })
        $kept = 0
        foreach ($w in $pubParts) {
            if ($stop -contains $w.ToLower()) { continue }
            & $add $w
            $kept++
            if ($kept -ge 2) { break }
        }
        if ($pubParts.Count -ge 2) { & $add ($pubParts[0] + $pubParts[1]) }
    }
    return $set.ToArray()
}

function Get-AppMatchers {
    param([string]$DisplayName, [string]$Publisher = '')
    $stop = @('inc','llc','ltd','corp','corporation','technologies','technology','software','team','foundation','project','community','gmbh','limited','company','solutions','systems','labs','studio','group','the','and','for','co','app','desktop','client','suite','free','pro','professional','version','edition','package','packages','tool','tools','manager','windows','microsoft','update','updater')
    $set = New-Object System.Collections.Generic.List[string]
    foreach ($n in (Get-VariantNames -DisplayName $DisplayName -Publisher $Publisher)) {
        $k = ConvertTo-NameKey $n
        if ($k.Length -ge 3 -and -not $set.Contains($k)) { [void]$set.Add($k) }
    }
    foreach ($w in (@($DisplayName -split '\s+'))) {
        if (-not $w) { continue }
        if ($stop -contains $w.ToLower()) { continue }
        $k = ConvertTo-NameKey $w
        if ($k.Length -ge 4 -and -not $set.Contains($k)) { [void]$set.Add($k) }
    }
    return $set.ToArray()
}

function Get-RunningProcessPaths {
    if ($script:WorkerProcPaths.Count -gt 0 -and $script:WorkerProcPathsTime -and (((Get-Date) - $script:WorkerProcPathsTime).TotalSeconds -lt 60)) {
        return $script:WorkerProcPaths
    }
    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        try {
            $pp = $p.Path
            if ($pp) { [void]$paths.Add($pp) }
        } catch { }
    }
    $script:WorkerProcPaths = $paths.ToArray()
    $script:WorkerProcPathsTime = Get-Date
    return $script:WorkerProcPaths
}

function Get-LeftoverAllowedRoots {
    $roots = New-Object System.Collections.Generic.List[string]
    $candidates = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, (Join-Path $env:LOCALAPPDATA 'Programs'), $env:LOCALAPPDATA, $env:APPDATA)
    foreach ($cand in $candidates) {
        if (-not $cand) { continue }
        $n = Get-NormalizedPath $cand
        if (-not $n) { continue }
        $dup = $false
        foreach ($r in $roots) { if ($r -eq $n) { $dup = $true; break } }
        if ((-not $dup) -and (Test-Path -LiteralPath $n)) { [void]$roots.Add($n) }
    }
    return $roots.ToArray()
}

function Test-SafeLeftoverPath {
    param([string]$Path)
    $res = @{ Safe = $false; Reason = 'unknown'; InUse = $false }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        $res.Reason = 'path does not exist'
        return $res
    }
    $full = Get-NormalizedPath $Path
    if (-not $full) { $res.Reason = 'could not normalize path'; return $res }
    $root = $null
    foreach ($r in (Get-LeftoverAllowedRoots)) {
        if (Test-PathUnder $full $r) {
            if ((-not $root) -or ($r.Length -gt $root.Length)) { $root = $r }
        }
    }
    if (-not $root) { $res.Reason = 'outside the allowed cleanup roots'; return $res }
    $rel = $full.Substring($root.Length).Trim('\')
    if (-not $rel) { $res.Reason = 'is a root folder itself'; return $res }
    foreach ($seg in ($rel -split '\\')) {
        if ($ProtectedFolderNames -contains $seg.ToLower()) { $res.Reason = 'protected folder: ' + $seg; return $res }
    }
    $cur = $full
    while ($cur -and $cur.Length -gt $root.Length) {
        $it = Get-Item -LiteralPath $cur -Force -ErrorAction SilentlyContinue
        if ($it -and ([int]($it.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            $res.Reason = 'junction/symlink (reparse point)'
            return $res
        }
        $cur = Split-Path -Path $cur -Parent
    }
    $res.Safe = $true
    $res.Reason = ''
    foreach ($pp in (Get-RunningProcessPaths)) {
        if (Test-PathUnder $pp $full) { $res.InUse = $true; break }
    }
    return $res
}

function Get-FolderStats {
    param([string]$Path)
    $size = [long]0
    $count = 0
    try {
        foreach ($f in (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue)) {
            try { $size += [long]$f.Length; $count++ } catch { }
            if ($count -ge 300000) { break }
        }
    } catch { }
    $mb = [math]::Round($size / 1048576.0, 1)
    return @{ SizeMB = $mb; FileCount = $count }
}

function Find-FolderLeftovers {
    param([string[]]$Matchers)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($root in (Get-LeftoverAllowedRoots)) {
        $children = @()
        try { $children = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue) } catch { }
        foreach ($d in $children) {
            $key = ConvertTo-NameKey $d.Name
            if (-not $key) { continue }
            $hit = $false
            foreach ($m in $Matchers) {
                if ($m -and $key.Contains($m)) { $hit = $true; break }
            }
            if (-not $hit) { continue }
            $safe = Test-SafeLeftoverPath $d.FullName
            $size = '-'
            $files = 0
            if ([bool]$safe.Safe) {
                $st = Get-FolderStats $d.FullName
                $size = [string]$st.SizeMB
                $files = [int]$st.FileCount
            }
            [void]$out.Add([PSCustomObject]@{
                Type   = 'Folder'
                Path   = $d.FullName
                Detail = ($root + '  |  ' + $size + ' MB  |  ' + $files + ' files')
                Safe   = [bool]$safe.Safe
                Reason = [string]$safe.Reason
                InUse  = [bool]$safe.InUse
            })
        }
    }
    return $out.ToArray()
}

function Find-RegistryLeftovers {
    param([string[]]$Matchers)
    $denyKeys = @('microsoft','windows','policies','classes','clients','registeredapplications','internet explorer','odbc','wow6432node','scheme','shell','typedpaths')
    $bases = @('HKCU:\Software', 'HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\Wow6432Node')
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($base in $bases) {
        if (-not (Test-Path -LiteralPath $base)) { continue }
        $keys = @()
        try { $keys = @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue) } catch { }
        foreach ($k in $keys) {
            $name = [string]$k.PSChildName
            $norm = ConvertTo-NameKey $name
            if (-not $norm) { continue }
            if ($denyKeys -contains $norm) { continue }
            $hit = $false
            foreach ($m in $Matchers) {
                if ($m -and $norm.Contains($m)) { $hit = $true; break }
            }
            if (-not $hit) { continue }
            $hk = ([string]$k.PSPath) -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
            [void]$out.Add([PSCustomObject]@{
                Type   = 'RegistryKey'
                Path   = $hk
                Detail = $hk
                Safe   = $true
                Reason = ''
                InUse  = $false
            })
        }
    }
    return $out.ToArray()
}

function Find-TaskLeftovers {
    param([string[]]$Matchers)
    $out = New-Object System.Collections.Generic.List[object]
    $tasks = @()
    try { $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue) } catch { }
    foreach ($t in $tasks) {
        $tp = [string]$t.TaskPath
        if ($tp -like '\Microsoft\*') { continue }
        $key = ConvertTo-NameKey ([string]$t.TaskName)
        if (-not $key) { continue }
        $hit = $false
        foreach ($m in $Matchers) {
            if ($m -and $key.Contains($m)) { $hit = $true; break }
        }
        if (-not $hit) { continue }
        [void]$out.Add([PSCustomObject]@{
            Type   = 'Task'
            Path   = ($tp + [string]$t.TaskName)
            Detail = ($tp + [string]$t.TaskName)
            Safe   = $true
            Reason = ''
            InUse  = $false
        })
    }
    return $out.ToArray()
}

function Find-ServiceLeftovers {
    param([string[]]$Matchers)
    $out = New-Object System.Collections.Generic.List[object]
    $svcs = @()
    try { $svcs = @(Get-Service -ErrorAction SilentlyContinue) } catch { }
    foreach ($s in $svcs) {
        $comb = ([string]$s.Name + ' ' + [string]$s.DisplayName)
        $low = $comb.ToLower()
        if ($low.Contains('microsoft') -or $low.Contains('windows')) { continue }
        $key = ConvertTo-NameKey $comb
        $hit = $false
        foreach ($m in $Matchers) {
            if ($m -and $key.Contains($m)) { $hit = $true; break }
        }
        if (-not $hit) { continue }
        [void]$out.Add([PSCustomObject]@{
            Type   = 'Service'
            Path   = [string]$s.Name
            Detail = ([string]$s.Name + '  (' + [string]$s.DisplayName + ')  [' + $s.StartType.ToString() + ']')
            Safe   = $true
            Reason = ''
            InUse  = $false
        })
    }
    return $out.ToArray()
}

function Find-ShortcutLeftovers {
    param([string[]]$Matchers, [string[]]$AppFolders = @())
    $out = New-Object System.Collections.Generic.List[object]
    $locations = @(
        [Environment]::GetFolderPath('CommonDesktopDirectory'),
        [Environment]::GetFolderPath('Desktop'),
        [Environment]::GetFolderPath('CommonStartMenu'),
        [Environment]::GetFolderPath('StartMenu')
    )
    $ws = $null
    try { $ws = New-Object -ComObject WScript.Shell } catch { }
    foreach ($loc in $locations) {
        if (-not $loc -or -not (Test-Path -LiteralPath $loc)) { continue }
        $files = @()
        try { $files = @(Get-ChildItem -LiteralPath $loc -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -ieq '.lnk' }) } catch { }
        foreach ($f in $files) {
            $key = ConvertTo-NameKey $f.BaseName
            $hit = $false
            foreach ($m in $Matchers) {
                if ($m -and $key.Contains($m)) { $hit = $true; break }
            }
            if ((-not $hit) -and $ws -and $AppFolders.Count -gt 0) {
                try {
                    $sc = $ws.CreateShortcut($f.FullName)
                    $tp = [string]$sc.TargetPath
                    if ($tp) {
                        foreach ($af in $AppFolders) {
                            if (Test-PathUnder $tp $af) { $hit = $true; break }
                        }
                    }
                } catch { }
            }
            if (-not $hit) { continue }
            [void]$out.Add([PSCustomObject]@{
                Type   = 'Shortcut'
                Path   = $f.FullName
                Detail = $f.FullName
                Safe   = $true
                Reason = ''
                InUse  = $false
            })
        }
    }
    if ($ws) { try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ws) | Out-Null } catch { } }
    return $out.ToArray()
}

function Find-RunValueLeftovers {
    param([string[]]$Matchers)
    $out = New-Object System.Collections.Generic.List[object]
    $runs = @(
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($rk in $runs) {
        if (-not (Test-Path -LiteralPath $rk)) { continue }
        try {
            $key = Get-Item -LiteralPath $rk
            foreach ($vn in $key.GetValueNames()) {
                $data = [string]$key.GetValue($vn, '')
                $comb = [string]$vn + ' ' + $data
                $norm = ConvertTo-NameKey $comb
                $hit = $false
                foreach ($m in $Matchers) {
                    if ($m -and $norm.Contains($m)) { $hit = $true; break }
                }
                if (-not $hit) { continue }
                [void]$out.Add([PSCustomObject]@{
                    Type   = 'RunValue'
                    Path   = ($rk + '|' + $vn)
                    Detail = ([string]$vn + '  ->  ' + $data)
                    Safe   = $true
                    Reason = ''
                    InUse  = $false
                })
            }
        } catch { }
    }
    return $out.ToArray()
}

function Get-ExeFromCommandLine {
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return $null }
    $c = $Cmd.Trim()
    if ($c.StartsWith('"')) {
        $i = $c.IndexOf('"', 1)
        if ($i -gt 1) { return $c.Substring(1, $i - 1) }
    }
    $m = [regex]::Match($c, '(?i)^(.*?\.exe)(\s|$)')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Invoke-UninstallCommand {
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return -1 }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $env:ComSpec
        $psi.Arguments = '/c ' + $Cmd
        $psi.UseShellExecute = $false
        $p = [System.Diagnostics.Process]::Start($psi)
        $ok = $p.WaitForExit(900000)
        if (-not $ok) {
            try { $p.Kill() } catch { }
            return -2
        }
        return $p.ExitCode
    } catch {
        return -3
    }
}

function Get-UninstallEntries {
    $bases = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($base in $bases) {
        if (-not (Test-Path -LiteralPath $base)) { continue }
        $keys = @()
        try { $keys = @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue) } catch { }
        foreach ($k in $keys) {
            try {
                $key = Get-Item -LiteralPath $k.PSPath
                if ($key.GetValueNames() -contains 'ParentKeyName') { continue }
                $dn = [string]$key.GetValue('DisplayName', '')
                if (-not $dn) { continue }
                if ([int]$key.GetValue('SystemComponent', 0) -eq 1) { continue }
                $rel = [string]$key.GetValue('ReleaseType', '')
                if ($rel -match '(?i)update|hotfix|security|servicepack') { continue }
                if ($dn -match '(?i)^(KB\d|Update for |Security Update|Hotfix)') { continue }
                $hk = ([string]$k.PSPath) -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
                [void]$out.Add([PSCustomObject]@{
                    DisplayName         = $dn
                    Publisher           = [string]$key.GetValue('Publisher', '')
                    Version             = [string]$key.GetValue('DisplayVersion', '')
                    UninstallString     = [string]$key.GetValue('UninstallString', '')
                    QuietUninstallString = [string]$key.GetValue('QuietUninstallString', '')
                    InstallLocation     = [string]$key.GetValue('InstallLocation', '')
                    DisplayIcon         = [string]$key.GetValue('DisplayIcon', '')
                    KeyPath             = $hk
                })
            } catch { }
        }
    }
    return $out.ToArray()
}

function Test-WinGetAvailable {
    try {
        $v = (& winget.exe --version 2>$null | Out-String)
        if ($v -and $v.Trim().Length -gt 0) { return $true }
    } catch { }
    return $false
}

function ConvertFrom-WingetTable {
    param([string]$Text)
    $rows = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($Text)) { return $rows.ToArray() }
    $lines = @($Text -split "`r?`n")
    $sepIdx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*-{3,}') { $sepIdx = $i; break }
    }
    if ($sepIdx -lt 1) { return $rows.ToArray() }
    $hdr = [string]$lines[$sepIdx - 1]
    $tokens = @('Name', 'Id', 'Version', 'Available', 'Source', 'Match')
    $cols = New-Object System.Collections.Generic.List[object]
    $searchFrom = 0
    foreach ($tok in $tokens) {
        $idx = $hdr.IndexOf($tok, $searchFrom)
        if ($idx -ge 0) {
            [void]$cols.Add([PSCustomObject]@{ Name = $tok; Start = $idx })
            $searchFrom = $idx + 1
        }
    }
    if ($cols.Count -lt 2) { return $rows.ToArray() }
    for ($i = $sepIdx + 1; $i -lt $lines.Count; $i++) {
        $line = [string]$lines[$i]
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^\s*-{3,}\s*$') { continue }
        if ($line.Length -le $cols[0].Start) { continue }
        $vals = @{}
        for ($k = 0; $k -lt $cols.Count; $k++) {
            $start = [int]$cols[$k].Start
            $end = $line.Length
            if ($k + 1 -lt $cols.Count) { $end = [int]$cols[$k + 1].Start }
            if ($start -ge $line.Length) { $vals[$cols[$k].Name] = ''; continue }
            if ($end -gt $line.Length) { $end = $line.Length }
            if ($end -le $start) { $vals[$cols[$k].Name] = ''; continue }
            $vals[$cols[$k].Name] = $line.Substring($start, $end - $start).Trim()
        }
        if (-not $vals['Id']) { continue }
        if ($vals['Id'] -notmatch '^[\w\.\-\+]+$') { continue }
        if ($vals['Name'] -eq 'Name' -and $vals['Id'] -eq 'Id') { continue }
        [void]$rows.Add([PSCustomObject]@{
            Name      = [string]$vals['Name']
            Id        = [string]$vals['Id']
            Version   = [string]$vals['Version']
            Available = [string]$vals['Available']
            Source    = [string]$vals['Source']
        })
    }
    return $rows.ToArray()
}
'@

. ([scriptblock]::Create($WorkerSrc))


$script:DlgDepth = 0

function Enter-DialogScope {
    $script:DlgDepth = [int]$script:DlgDepth + 1
}

function Exit-DialogScope {
    $script:DlgDepth = [int]$script:DlgDepth - 1
    if ($script:DlgDepth -lt 0) { $script:DlgDepth = 0 }
}

if (-not ('StweakRecycle' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class StweakRecycle
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEOPSTRUCT
    {
        public IntPtr hwnd;
        public uint wFunc;
        [MarshalAs(UnmanagedType.LPWStr)] public string pFrom;
        [MarshalAs(UnmanagedType.LPWStr)] public string pTo;
        public ushort fFlags;
        public bool fAnyOperationsAborted;
        public IntPtr hNameMappings;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpszProgressTitle;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHFileOperation(ref SHFILEOPSTRUCT lpFileOp);

    public static bool Recycle(string path)
    {
        if (string.IsNullOrEmpty(path)) { return false; }
        SHFILEOPSTRUCT op = new SHFILEOPSTRUCT();
        op.wFunc = 3;
        op.pFrom = path + "\0";
        op.pTo = null;
        op.fFlags = 0x0004 | 0x0010 | 0x0040 | 0x0400;
        op.fAnyOperationsAborted = false;
        int rc = SHFileOperation(ref op);
        return (rc == 0) && !op.fAnyOperationsAborted;
    }
}
'@
}

function Move-ToRecycleBinSilent {
    param([string]$Path)
    if (-not $Path) { return $false }
    if ($Path.Length -gt 255) { return $false }
    try {
        $ok = [StweakRecycle]::Recycle($Path)
        if ($ok) { Write-FileLog ('Sent to Recycle Bin: ' + $Path) }
        else { Write-FileLog ('Could not send to Recycle Bin: ' + $Path) }
        return [bool]$ok
    } catch {
        Write-FileLog ('Recycle error for ' + $Path + ': ' + $_.Exception.Message)
        return $false
    }
}

$UninstallScanBody = @'
try {
    $app = [string]$Payload['DisplayName']
    $pub = [string]$Payload['Publisher']
    $installLoc = [string]$Payload['InstallLocation']
    $uninstallCmd = [string]$Payload['UninstallCommand']
    $runUninstaller = [bool]$Payload['RunUninstaller']

    W('Deep scan started for: ' + $app)
    if ($pub) { W('Publisher: ' + $pub) }

    $matchers = Get-AppMatchers -DisplayName $app -Publisher $pub
    W('Name patterns: ' + ($matchers -join ', '))

    if ($runUninstaller -and $uninstallCmd) {
        W('Running the official uninstaller...')
        W('Command: ' + $uninstallCmd)
        $code = Invoke-UninstallCommand -Cmd $uninstallCmd
        W('Uninstaller exit code: ' + $code)
        Start-Sleep -Seconds 3
    } elseif ($runUninstaller) {
        W('No uninstall command available - skipping the official uninstaller.')
    }

    $items = New-Object System.Collections.Generic.List[object]

    W('Scanning folders...')
    foreach ($it in (Find-FolderLeftovers -Matchers $matchers)) { $items.Add($it) }
    W('Folders found: ' + $items.Count)

    W('Scanning registry keys...')
    $rc = $items.Count
    foreach ($it in (Find-RegistryLeftovers -Matchers $matchers)) { $items.Add($it) }
    W('Registry keys found: ' + ($items.Count - $rc))

    W('Scanning scheduled tasks...')
    $rc = $items.Count
    foreach ($it in (Find-TaskLeftovers -Matchers $matchers)) { $items.Add($it) }
    W('Scheduled tasks found: ' + ($items.Count - $rc))

    W('Scanning services...')
    $rc = $items.Count
    foreach ($it in (Find-ServiceLeftovers -Matchers $matchers)) { $items.Add($it) }
    W('Services found: ' + ($items.Count - $rc))

    W('Scanning shortcuts...')
    $rc = $items.Count
    $folders = @()
    foreach ($it in $items) { if ($it.Type -eq 'Folder') { $folders += $it.Path } }
    if ($installLoc -and (Test-Path -LiteralPath $installLoc)) { $folders += $installLoc }
    foreach ($it in (Find-ShortcutLeftovers -Matchers $matchers -AppFolders $folders)) { $items.Add($it) }
    W('Shortcuts found: ' + ($items.Count - $rc))

    W('Scanning startup entries (Run keys)...')
    $rc = $items.Count
    foreach ($it in (Find-RunValueLeftovers -Matchers $matchers)) { $items.Add($it) }
    W('Startup entries found: ' + ($items.Count - $rc))

    W('Scanning installed-programs entries...')
    $rc = $items.Count
    foreach ($ue in (Get-UninstallEntries)) {
        $key = ConvertTo-NameKey $ue.DisplayName
        $hit = $false
        foreach ($m in $matchers) { if ($m -and $key.Contains($m)) { $hit = $true; break } }
        if ($hit) {
            $items.Add([PSCustomObject]@{
                Type   = 'UninstallEntry'
                Path   = $ue.KeyPath
                Detail = ($ue.DisplayName + '  ' + $ue.Version)
                Safe   = $true
                Reason = ''
                InUse  = $false
            })
        }
    }
    W('Installed-programs entries found: ' + ($items.Count - $rc))

    $result = [PSCustomObject]@{
        App      = $app
        Publisher = $pub
        Matchers = $matchers
        Created  = (Get-Date).ToString('s')
        Items    = $items.ToArray()
    }
    $json = $result | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText(($log + '.json'), $json, (New-Object System.Text.UTF8Encoding($false)))
    W('Scan complete: ' + $items.Count + ' leftover items found.')
    W('DONE')
} catch {
    W('ERROR: ' + $_.Exception.Message)
    throw
}
'@

function Get-QuarantineManifest {
    if (Test-Path -LiteralPath $ManifestFile) {
        try {
            $raw = Get-Content -LiteralPath $ManifestFile -Raw -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $obj = $raw | ConvertFrom-Json -ErrorAction Stop
                $names = @($obj.PSObject.Properties.Name)
                $nextId = 1
                if ($names -contains 'nextId') { $nextId = [int]$obj.nextId }
                if ($nextId -lt 1) { $nextId = 1 }
                $entries = @()
                if ($names -contains 'entries') { $entries = @($obj.entries | Where-Object { $_ }) }
                return @{ nextId = $nextId; entries = $entries }
            }
        } catch {
            Write-FileLog ('WARNING: quarantine manifest was damaged (' + $_.Exception.Message + '); starting a new one.')
        }
    }
    return @{ nextId = 1; entries = @() }
}

function Save-QuarantineManifest {
    param($Manifest)
    $json = $Manifest | ConvertTo-Json -Depth 8
    $tmp = $ManifestFile + '.tmp'
    Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8 -ErrorAction Stop
    Move-Item -LiteralPath $tmp -Destination $ManifestFile -Force
}

function Add-QuarantineEntry {
    param([string]$App, [string]$Type, [string]$OriginalPath, [string]$QuarantinePath)
    $m = Get-QuarantineManifest
    $id = [int]$m.nextId
    $entry = [PSCustomObject]@{
        Id             = $id
        App            = $App
        Type           = $Type
        OriginalPath   = $OriginalPath
        QuarantinePath = $QuarantinePath
        Created        = (Get-Date).ToString('s')
        Restored       = $false
    }
    $m.entries = @($m.entries) + @($entry)
    $m.nextId = $id + 1
    Save-QuarantineManifest $m
    Write-FileLog ('Quarantined [' + $Type + '] ' + $OriginalPath + '  ->  ' + $QuarantinePath)
    return $entry
}

function Set-QuarantineEntryFlag {
    param([int]$Id, [string]$Field, $Value)
    $m = Get-QuarantineManifest
    $changed = $false
    foreach ($e in $m.entries) {
        if ([int]$e.Id -eq $Id) {
            if (@($e.PSObject.Properties.Name) -contains $Field) { $e.$Field = $Value }
            else { $e | Add-Member -NotePropertyName $Field -NotePropertyValue $Value -Force }
            $changed = $true
        }
    }
    if ($changed) { Save-QuarantineManifest $m }
}

function Get-QuarantineEntriesView {
    $m = Get-QuarantineManifest
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($raw in $m.entries) {
        $e = ConvertTo-HashtableDeep $raw
        $restored = $false
        if ($e.ContainsKey('Restored')) { $restored = [bool]$e['Restored'] }
        $qpath = ''
        if ($e.ContainsKey('QuarantinePath')) { $qpath = [string]$e['QuarantinePath'] }
        $exists = $false
        if ($qpath) { $exists = Test-Path -LiteralPath $qpath }
        [void]$out.Add([PSCustomObject]@{
            Id             = [int]$e['Id']
            App            = [string]$e['App']
            Type           = [string]$e['Type']
            OriginalPath   = [string]$e['OriginalPath']
            QuarantinePath = $qpath
            Created        = [string]$e['Created']
            Restored       = $restored
            PayloadExists  = $exists
            Raw            = $e
        })
    }
    return $out.ToArray()
}

function Move-ItemWithFallback {
    param([string]$From, [string]$To)
    try {
        Move-Item -LiteralPath $From -Destination $To -Force -ErrorAction Stop
        return $true
    } catch { }
    try {
        $it = Get-Item -LiteralPath $From -Force -ErrorAction Stop
        if ($it.PSIsContainer) {
            Copy-Item -LiteralPath $From -Destination $To -Recurse -Force -ErrorAction Stop
            Remove-Item -LiteralPath $From -Recurse -Force -ErrorAction Stop
        } else {
            Copy-Item -LiteralPath $From -Destination $To -Force -ErrorAction Stop
            Remove-Item -LiteralPath $From -Force -ErrorAction Stop
        }
        return $true
    } catch { return $false }
}

function Move-PathToQuarantine {
    param([string]$Path, [string]$App)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $leaf = Split-Path -Path $Path -Leaf
    if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = 'item' }
    $safeLeaf = ($leaf -replace '[^\w\.\-\ ]', '_')
    $dest = Join-Path $QuarantineDir ('q_' + (Get-Date -Format 'yyyyMMdd_HHmmss_fff') + '_' + $safeLeaf)
    if (Move-ItemWithFallback -From $Path -To $dest) { return $dest }
    return $null
}

function Backup-ScheduledTaskXml {
    param([string]$TaskFullName)
    $safe = ($TaskFullName -replace '[^\w\.\-\ ]', '_')
    $file = Join-Path $TaskBackupDir ($safe + '_' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.xml')
    try {
        $xml = (& schtasks.exe /query /tn $TaskFullName /xml 2>$null | Out-String)
        if ([string]::IsNullOrWhiteSpace($xml)) { return $null }
        [System.IO.File]::WriteAllText($file, $xml, [System.Text.Encoding]::Unicode)
        return $file
    } catch { return $null }
}

function Remove-LeftoverItem {
    param($Item, [string]$App = '', [string]$Mode = 'Quarantine')
    $h = ConvertTo-HashtableDeep $Item
    $type = [string]$h['Type']
    $path = [string]$h['Path']
    try {
        switch ($type) {
            'Folder' {
                if (-not (Test-Path -LiteralPath $path)) { return @{ Success = $true; Message = 'already gone' } }
                if ($Mode -eq 'Recycle') {
                    if ($path.Length -le 255) {
                        if (-not (Move-ToRecycleBinSilent -Path $path)) { throw 'could not send the folder to the Recycle Bin (it may be in use)' }
                    } else {
                        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($path, [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs, [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin)
                    }
                } elseif ($Mode -eq 'Delete') {
                    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
                    Write-FileLog ('Deleted folder: ' + $path)
                } else {
                    $qp = Move-PathToQuarantine -Path $path -App $App
                    if (-not $qp) { throw 'could not move the folder to quarantine' }
                    Add-QuarantineEntry -App $App -Type 'Folder' -OriginalPath $path -QuarantinePath $qp | Out-Null
                }
            }
            'Shortcut' {
                if (-not (Test-Path -LiteralPath $path)) { return @{ Success = $true; Message = 'already gone' } }
                if ($Mode -eq 'Recycle') {
                    if ($path.Length -le 255) {
                        if (-not (Move-ToRecycleBinSilent -Path $path)) { throw 'could not send the shortcut to the Recycle Bin (it may be in use)' }
                    } else {
                        [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($path, [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs, [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin)
                    }
                } elseif ($Mode -eq 'Delete') {
                    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                    Write-FileLog ('Deleted shortcut: ' + $path)
                } else {
                    $qp = Move-PathToQuarantine -Path $path -App $App
                    if (-not $qp) { throw 'could not move the shortcut to quarantine' }
                    Add-QuarantineEntry -App $App -Type 'Shortcut' -OriginalPath $path -QuarantinePath $qp | Out-Null
                }
            }
            'RegistryKey' {
                $rpath = ConvertTo-PSRegPath $path
                if (-not $rpath) { throw 'invalid registry path' }
                if (-not (Test-Path -LiteralPath $rpath)) { return @{ Success = $true; Message = 'already gone' } }
                if ($Mode -eq 'Delete') {
                    Remove-Item -LiteralPath $rpath -Recurse -Force -ErrorAction Stop
                    Write-FileLog ('Deleted registry key: ' + $path)
                } else {
                    $bk = Export-RegKeyBackup $rpath
                    if (-not $bk) { throw 'could not export the registry key' }
                    Add-QuarantineEntry -App $App -Type 'RegistryKey' -OriginalPath $path -QuarantinePath $bk | Out-Null
                    Remove-Item -LiteralPath $rpath -Recurse -Force -ErrorAction Stop
                }
            }
            'UninstallEntry' {
                $rpath = ConvertTo-PSRegPath $path
                if (-not $rpath) { throw 'invalid registry path' }
                if (-not (Test-Path -LiteralPath $rpath)) { return @{ Success = $true; Message = 'already gone' } }
                if ($Mode -eq 'Delete') {
                    Remove-Item -LiteralPath $rpath -Recurse -Force -ErrorAction Stop
                    Write-FileLog ('Deleted uninstall entry: ' + $path)
                } else {
                    $bk = Export-RegKeyBackup $rpath
                    if (-not $bk) { throw 'could not export the uninstall entry' }
                    Add-QuarantineEntry -App $App -Type 'UninstallEntry' -OriginalPath $path -QuarantinePath $bk | Out-Null
                    Remove-Item -LiteralPath $rpath -Recurse -Force -ErrorAction Stop
                }
            }
            'RunValue' {
                $parts = $path -split '\|', 2
                if ($parts.Count -lt 2) { throw 'invalid run value path' }
                $keyPath = ConvertTo-PSRegPath $parts[0]
                $valName = $parts[1]
                if (-not (Test-Path -LiteralPath $keyPath)) { return @{ Success = $true; Message = 'already gone' } }
                if ($Mode -eq 'Delete') {
                    Remove-ItemProperty -LiteralPath $keyPath -Name $valName -ErrorAction Stop
                    Write-FileLog ('Deleted run value: ' + $path)
                } else {
                    $bk = Export-RegKeyBackup $keyPath
                    if (-not $bk) { throw 'could not export the registry key' }
                    Add-QuarantineEntry -App $App -Type 'RunValue' -OriginalPath $path -QuarantinePath $bk | Out-Null
                    Remove-ItemProperty -LiteralPath $keyPath -Name $valName -ErrorAction Stop
                }
            }
            'Task' {
                $i = $path.LastIndexOf('\')
                if ($i -lt 0) { throw 'invalid task path' }
                $tPath = $path.Substring(0, $i + 1)
                $tName = $path.Substring($i + 1)
                if ($Mode -eq 'Quarantine') {
                    $tf = Backup-ScheduledTaskXml -TaskFullName $path
                    if (-not $tf) { throw 'could not export the scheduled task backup' }
                    Add-QuarantineEntry -App $App -Type 'Task' -OriginalPath $path -QuarantinePath $tf | Out-Null
                }
                Unregister-ScheduledTask -TaskPath $tPath -TaskName $tName -Confirm:$false -ErrorAction Stop
                Write-FileLog ('Removed scheduled task: ' + $path)
            }
            'Service' {
                $svcName = $path
                $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if (-not $svc) { return @{ Success = $true; Message = 'already gone' } }
                if ($Mode -eq 'Quarantine') {
                    $safe = ($svcName -replace '[^\w\.\-]', '_')
                    $file = Join-Path $TaskBackupDir ($safe + '_service_' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
                    try {
                        $info = (& sc.exe qc $svcName 2>$null | Out-String)
                        [System.IO.File]::WriteAllText($file, $info, (New-Object System.Text.UTF8Encoding($false)))
                        Add-QuarantineEntry -App $App -Type 'Service' -OriginalPath $svcName -QuarantinePath $file | Out-Null
                    } catch { }
                }
                try { if ($svc.Status -ne 'Stopped') { Stop-Service -Name $svcName -Force -ErrorAction Stop } } catch { }
                $del = (& sc.exe delete $svcName 2>&1 | Out-String)
                if ($LASTEXITCODE -ne 0) { throw ('sc.exe delete failed: ' + $del.Trim()) }
                Write-FileLog ('Removed service: ' + $svcName + ' (manual restore needed)')
            }
            default {
                return @{ Success = $false; Message = ('unknown item type: ' + $type) }
            }
        }
        return @{ Success = $true; Message = 'ok' }
    } catch {
        Write-FileLog ('Removal failed for ' + $path + ': ' + $_.Exception.Message)
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

function Restore-QuarantineEntry {
    param($Entry)
    $e = ConvertTo-HashtableDeep $Entry
    $type = [string]$e['Type']
    $orig = [string]$e['OriginalPath']
    $qp = [string]$e['QuarantinePath']
    try {
        switch ($type) {
            'Folder' {
                if (-not $qp -or -not (Test-Path -LiteralPath $qp)) { return @{ Success = $false; Message = 'quarantined folder is missing' } }
                if (Test-Path -LiteralPath $orig) { return @{ Success = $false; Message = 'the original path already exists' } }
                $parent = Split-Path -Path $orig -Parent
                if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
                if (-not (Move-ItemWithFallback -From $qp -To $orig)) { throw 'could not move the folder back' }
            }
            'Shortcut' {
                if (-not $qp -or -not (Test-Path -LiteralPath $qp)) { return @{ Success = $false; Message = 'quarantined shortcut is missing' } }
                if (Test-Path -LiteralPath $orig) { return @{ Success = $false; Message = 'the original path already exists' } }
                $parent = Split-Path -Path $orig -Parent
                if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
                if (-not (Move-ItemWithFallback -From $qp -To $orig)) { throw 'could not move the shortcut back' }
            }
            'RegistryKey' {
                if (-not $qp -or -not (Test-Path -LiteralPath $qp)) { return @{ Success = $false; Message = 'quarantined .reg file is missing' } }
                & reg.exe import $qp | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'reg import failed' }
            }
            'UninstallEntry' {
                if (-not $qp -or -not (Test-Path -LiteralPath $qp)) { return @{ Success = $false; Message = 'quarantined .reg file is missing' } }
                & reg.exe import $qp | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'reg import failed' }
            }
            'RunValue' {
                if (-not $qp -or -not (Test-Path -LiteralPath $qp)) { return @{ Success = $false; Message = 'quarantined .reg file is missing' } }
                & reg.exe import $qp | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'reg import failed' }
            }
            'Task' {
                if (-not $qp -or -not (Test-Path -LiteralPath $qp)) { return @{ Success = $false; Message = 'quarantined task XML is missing' } }
                $out = (& schtasks.exe /create /tn $orig /xml $qp /f 2>&1 | Out-String)
                if ($LASTEXITCODE -ne 0) { throw ('schtasks restore failed: ' + $out.Trim()) }
            }
            'Service' {
                return @{ Success = $false; Message = 'services cannot be restored automatically; the saved configuration is in: ' + $qp }
            }
            default {
                return @{ Success = $false; Message = ('unknown item type: ' + $type) }
            }
        }
        Set-QuarantineEntryFlag -Id ([int]$e['Id']) -Field 'Restored' -Value $true
        Write-FileLog ('Restored from quarantine: ' + $orig)
        return @{ Success = $true; Message = 'restored' }
    } catch {
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

function Remove-QuarantineEntry {
    param($Entry)
    $e = ConvertTo-HashtableDeep $Entry
    $qp = [string]$e['QuarantinePath']
    try {
        if ($qp -and (Test-Path -LiteralPath $qp)) {
            Remove-Item -LiteralPath $qp -Recurse -Force -ErrorAction Stop
        }
        Set-QuarantineEntryFlag -Id ([int]$e['Id']) -Field 'Restored' -Value $true
        Write-FileLog ('Quarantine payload deleted: ' + $qp)
        return @{ Success = $true; Message = 'deleted' }
    } catch {
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

$ReviewXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="STweak - Review leftovers" Width="920" Height="640"
        WindowStartupLocation="CenterOwner" Background="#FF0B0F17" Foreground="#FFE8ECF4">
  <Window.Resources>
    <Style TargetType="TextBlock">
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
    </Style>
    <Style TargetType="Button">
      <Setter Property="Background" Value="#FF1B2436"/>
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
      <Setter Property="BorderBrush" Value="#FF2A3B5C"/>
      <Setter Property="Padding" Value="12,4"/>
    </Style>
  </Window.Resources>
  <DockPanel Margin="10">
    <StackPanel DockPanel.Dock="Top">
      <TextBlock x:Name="TxtRevHeader" FontSize="16" FontWeight="Bold" Text="Leftovers"/>
      <TextBlock x:Name="TxtRevSub" Margin="0,4,0,8" Foreground="#FF8A94A8" TextWrapping="Wrap"
                 Text="Review the items below. Quarantine is the safe default: nothing is lost until you delete the quarantine."/>
    </StackPanel>
    <Border DockPanel.Dock="Bottom" Margin="0,8,0,0">
      <StackPanel>
        <StackPanel Orientation="Horizontal">
          <RadioButton x:Name="RbQuarantine" Foreground="#FFE8ECF4" Content="Quarantine (recommended)" IsChecked="True" Margin="0,0,16,0"/>
          <RadioButton x:Name="RbDelete" Foreground="#FFE8ECF4" Content="Delete permanently" Margin="0,0,16,0"/>
          <RadioButton x:Name="RbRecycle" Foreground="#FFE8ECF4" Content="Send folders/files to Recycle Bin"/>
        </StackPanel>
        <StackPanel Orientation="Horizontal" Margin="0,10,0,0">
          <TextBlock Foreground="#FF8A94A8" VerticalAlignment="Center" Margin="0,0,8,0"
                     Text="For permanent delete, type DELETE here to enable the button:"/>
          <TextBox x:Name="TxtRevConfirm" Width="130" Background="#FF0F1622" Foreground="#FFE8ECF4"
                   CaretBrush="#FFE8ECF4" BorderBrush="#FF26324A"/>
        </StackPanel>
        <TextBlock x:Name="TxtRevStatus" Margin="0,8,0,0" Foreground="#FFFFC66D" TextWrapping="Wrap"/>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,8,0,0">
          <Button x:Name="BtnRevAll" Content="Select all" Padding="10,4" Margin="0,0,8,0"/>
          <Button x:Name="BtnRevNone" Content="Select none" Padding="10,4" Margin="0,0,8,0"/>
          <Button x:Name="BtnRevExecute" Content="Execute" Padding="18,4" Margin="0,0,8,0"
                  Background="#FF3D63D6" BorderBrush="#FF3D63D6"/>
          <Button x:Name="BtnRevCancel" Content="Cancel" Padding="18,4" IsCancel="True"/>
        </StackPanel>
      </StackPanel>
    </Border>
    <Border BorderBrush="#FF1F2A40" BorderThickness="1" Background="#FF121A29">
      <ScrollViewer VerticalScrollBarVisibility="Auto">
        <StackPanel x:Name="SpRevPanel" Margin="6"/>
      </ScrollViewer>
    </Border>
  </DockPanel>
</Window>
'@

$script:RevDlg = $null
$script:RevReturn = $null
$script:RevAppName = ''
$script:RevSpPanel = $null
$script:RevTxtHeader = $null
$script:RevTxtSub = $null
$script:RevTxtConfirm = $null
$script:RevTxtStatus = $null
$script:RevBtnExecute = $null
$script:RevRbQuarantine = $null
$script:RevRbDelete = $null
$script:RevRbRecycle = $null

function Initialize-ReviewDialog {
    if ($script:RevDlg) { return }
    [xml]$xamlDoc = $ReviewXaml
    $dlg = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xamlDoc))
    $script:RevDlg = $dlg
    $script:RevSpPanel = $dlg.FindName('SpRevPanel')
    $script:RevTxtHeader = $dlg.FindName('TxtRevHeader')
    $script:RevTxtSub = $dlg.FindName('TxtRevSub')
    $script:RevTxtConfirm = $dlg.FindName('TxtRevConfirm')
    $script:RevTxtStatus = $dlg.FindName('TxtRevStatus')
    $script:RevBtnExecute = $dlg.FindName('BtnRevExecute')
    $script:RevRbQuarantine = $dlg.FindName('RbQuarantine')
    $script:RevRbDelete = $dlg.FindName('RbDelete')
    $script:RevRbRecycle = $dlg.FindName('RbRecycle')
    $dlg.FindName('BtnRevCancel').Add_Click({ $script:RevReturn = $null; $script:RevDlg.Close() })
    $dlg.FindName('BtnRevAll').Add_Click({ Set-RevChecks $true })
    $dlg.FindName('BtnRevNone').Add_Click({ Set-RevChecks $false })
    $script:RevBtnExecute.Add_Click({ Invoke-RevExecute })
    $script:RevTxtConfirm.Add_TextChanged({ Update-RevEnable })
    $script:RevRbDelete.Add_Checked({ Update-RevEnable })
    $script:RevRbQuarantine.Add_Checked({ Update-RevEnable })
    $script:RevRbRecycle.Add_Checked({ Update-RevEnable })
}

function Update-RevEnable {
    if (-not $script:RevDlg) { return }
    $need = ($script:RevRbDelete.IsChecked -eq $true)
    $ok = (-not $need) -or ($script:RevTxtConfirm.Text -eq 'DELETE')
    $script:RevBtnExecute.IsEnabled = $ok
}

function Set-RevChecks {
    param([bool]$State)
    foreach ($cb in $script:RevSpPanel.Children) {
        if ($cb -is [System.Windows.Controls.CheckBox] -and $cb.IsEnabled) { $cb.IsChecked = $State }
    }
}

function Invoke-RevExecute {
    $mode = 'Quarantine'
    if ($script:RevRbDelete.IsChecked -eq $true) { $mode = 'Delete' }
    elseif ($script:RevRbRecycle.IsChecked -eq $true) { $mode = 'Recycle' }

    $selected = New-Object System.Collections.Generic.List[object]
    foreach ($cb in $script:RevSpPanel.Children) {
        if ($cb -is [System.Windows.Controls.CheckBox] -and $cb.IsChecked -eq $true) { $selected.Add($cb.Tag) }
    }
    if ($selected.Count -eq 0) {
        $script:RevTxtStatus.Text = 'No items are selected.'
        return
    }

    $ok = 0
    $fail = 0
    $failures = New-Object System.Collections.Generic.List[string]
    $done = 0
    [System.Windows.Input.Mouse]::OverrideCursor = [System.Windows.Input.Cursors]::Wait
    try {
        foreach ($item in $selected) {
            $done++
            $script:RevTxtStatus.Text = ('Working... ' + $done + ' / ' + $selected.Count + '  ->  ' + [string]$item.Path)
            $script:RevTxtStatus.UpdateLayout()
            $r = Remove-LeftoverItem -Item $item -App $script:RevAppName -Mode $mode
            if ($r.Success) { $ok++ }
            else { $fail++; [void]$failures.Add([string]$item.Path + '  ->  ' + [string]$r.Message) }
        }
    } finally {
        [System.Windows.Input.Mouse]::OverrideCursor = $null
    }
    $script:RevReturn = @{
        App      = $script:RevAppName
        Mode     = $mode
        Ok       = $ok
        Fail     = $fail
        Failures = $failures.ToArray()
    }
    $script:RevDlg.Close()
}

function Show-LeftoverReviewDialog {
    param([string]$AppName, $Items)
    Initialize-ReviewDialog
    $script:RevReturn = $null
    $script:RevAppName = $AppName
    $script:RevTxtHeader.Text = 'Leftovers found for: ' + $AppName
    $script:RevTxtConfirm.Text = ''
    $script:RevRbQuarantine.IsChecked = $true
    $script:RevTxtStatus.Text = ''
    $script:RevSpPanel.Children.Clear()
    $count = 0
    foreach ($item in $Items) {
        $count++
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Margin = New-Object System.Windows.Thickness(4, 3, 4, 3)
        $label = '[' + [string]$item.Type + ']  ' + [string]$item.Path
        if ($item.Detail -and ([string]$item.Detail -ne [string]$item.Path)) { $label = $label + '   -   ' + [string]$item.Detail }
        if ($item.InUse -eq $true) { $label = $label + '   [in use - close the app first]' }
        if ($item.Safe -eq $true) {
            $cb.IsChecked = ($item.InUse -ne $true)
            $cb.Content = $label
        } else {
            $cb.IsChecked = $false
            $cb.IsEnabled = $false
            $cb.Content = $label + '   [PROTECTED - ' + [string]$item.Reason + ']'
            $cb.Foreground = [System.Windows.Media.Brushes]::Gray
        }
        $cb.Tag = $item
        [void]$script:RevSpPanel.Children.Add($cb)
    }
    $script:RevTxtSub.Text = 'Review the ' + $count + ' item(s) below. Quarantine is the safe default: nothing is lost until you delete the quarantine.'
    Update-RevEnable
    if ($script:Window) { $script:RevDlg.Owner = $script:Window }
    Enter-DialogScope
    try { $script:RevDlg.ShowDialog() | Out-Null }
    finally { Exit-DialogScope }
    return $script:RevReturn
}


$MainXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="STweak v2" Width="1280" Height="830" MinWidth="1150" MinHeight="700"
        WindowStartupLocation="CenterScreen" Background="#FF0B0F17" Foreground="#FFE8ECF4"
        FontFamily="Segoe UI" FontSize="12" TextOptions.TextFormattingMode="Display">
  <Window.Resources>
    <Style TargetType="TextBlock">
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
    </Style>
    <Style TargetType="Button">
      <Setter Property="Background" Value="#FF1B2436"/>
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
      <Setter Property="BorderBrush" Value="#FF2A3B5C"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="12,4"/>
      <Setter Property="Margin" Value="0,0,6,0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF24314A"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF182238"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.45"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="NavButton" TargetType="Button">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="#FFC7D0E0"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="10,9"/>
      <Setter Property="Margin" Value="0,1,0,1"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" CornerRadius="8" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF182238"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF101A2C"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="AccentButton" TargetType="Button">
      <Setter Property="Background" Value="#FF3D63D6"/>
      <Setter Property="Foreground" Value="#FFFFFFFF"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="16,7"/>
      <Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" CornerRadius="8" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF5177E8"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF3355BE"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.45"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="GhostButton" TargetType="Button">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="#FFC7D0E0"/>
      <Setter Property="BorderBrush" Value="#FF2A3B5C"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="16,7"/>
      <Setter Property="Margin" Value="0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF182238"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF101A2C"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="CardButton" TargetType="Button">
      <Setter Property="Background" Value="#FF121A29"/>
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
      <Setter Property="BorderBrush" Value="#FF1F2A40"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="14"/>
      <Setter Property="Margin" Value="0,0,10,0"/>
      <Setter Property="MinHeight" Value="150"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="VerticalContentAlignment" Value="Top"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="12" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Top"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF182238"/>
                <Setter TargetName="Bd" Property="BorderBrush" Value="#FF2A3B5C"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF101A2C"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#FF0F1622"/>
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
      <Setter Property="CaretBrush" Value="#FFE8ECF4"/>
      <Setter Property="SelectionBrush" Value="#FF3355BE"/>
      <Setter Property="BorderBrush" Value="#FF26324A"/>
      <Setter Property="Padding" Value="5,3"/>
    </Style>
    <Style TargetType="ComboBox">
      <Setter Property="Background" Value="#FF0F1622"/>
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
      <Setter Property="BorderBrush" Value="#FF26324A"/>
      <Setter Property="Padding" Value="7,3"/>
      <Setter Property="MinHeight" Value="26"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBox">
            <Grid>
              <ToggleButton x:Name="PART_Toggle" Focusable="False" ClickMode="Press"
                            IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}">
                <ToggleButton.Template>
                  <ControlTemplate TargetType="ToggleButton">
                    <Border x:Name="Bd" Background="#FF0F1622" BorderBrush="#FF26324A"
                            BorderThickness="1" CornerRadius="6">
                      <TextBlock Text="&#xE70D;" FontFamily="Segoe MDL2 Assets" FontSize="10"
                                 Foreground="#FF8A94A8" Margin="0,0,8,0"
                                 HorizontalAlignment="Right" VerticalAlignment="Center"/>
                    </Border>
                    <ControlTemplate.Triggers>
                      <Trigger Property="IsMouseOver" Value="True">
                        <Setter TargetName="Bd" Property="Background" Value="#FF121A29"/>
                        <Setter TargetName="Bd" Property="BorderBrush" Value="#FF2A3B5C"/>
                      </Trigger>
                    </ControlTemplate.Triggers>
                  </ControlTemplate>
                </ToggleButton.Template>
              </ToggleButton>
              <ContentPresenter Margin="8,0,40,0" HorizontalAlignment="Left" VerticalAlignment="Center"
                                IsHitTestVisible="False"
                                Content="{TemplateBinding SelectionBoxItem}"
                                ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                                ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}"
                                ContentStringFormat="{TemplateBinding SelectionBoxItemStringFormat}"/>
              <Popup x:Name="PART_Popup" AllowsTransparency="True" Placement="Bottom" Focusable="False"
                     IsOpen="{Binding IsDropDownOpen, RelativeSource={RelativeSource TemplatedParent}}">
                <Border Background="#FF121A29" BorderBrush="#FF2A3B5C" BorderThickness="1" CornerRadius="6"
                        MinWidth="{Binding ActualWidth, RelativeSource={RelativeSource TemplatedParent}}"
                        MaxHeight="{TemplateBinding MaxDropDownHeight}"
                        Margin="0,2,0,0" Padding="4">
                  <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                    <ItemsPresenter KeyboardNavigation.DirectionalNavigation="Contained"/>
                  </ScrollViewer>
                </Border>
              </Popup>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.5"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ComboBoxItem">
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
      <Setter Property="Padding" Value="7,5"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBoxItem">
            <Border x:Name="Bd" Background="Transparent" CornerRadius="5" Margin="1"
                    Padding="{TemplateBinding Padding}">
              <ContentPresenter/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF182238"/>
              </Trigger>
              <Trigger Property="IsHighlighted" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF1B2A47"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF24365C"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="RadioButton">
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <StackPanel Orientation="Horizontal" Background="Transparent">
              <Border x:Name="Circle" Width="16" Height="16" CornerRadius="8" Background="#FF0F1622"
                      BorderBrush="#FF2A3B5C" BorderThickness="1" VerticalAlignment="Center">
                <Ellipse x:Name="Dot" Width="8" Height="8" Fill="#FFFFFFFF" Visibility="Collapsed"/>
              </Border>
              <ContentPresenter Margin="7,0,0,0" VerticalAlignment="Center" RecognizesAccessKey="True"/>
            </StackPanel>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Dot" Property="Visibility" Value="Visible"/>
                <Setter TargetName="Circle" Property="Background" Value="#FF3D63D6"/>
                <Setter TargetName="Circle" Property="BorderBrush" Value="#FF3D63D6"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Circle" Property="BorderBrush" Value="#FF5177E8"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.45"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <StackPanel Orientation="Horizontal" Background="Transparent">
              <Border x:Name="Box" Width="16" Height="16" CornerRadius="4" Background="#FF0F1622"
                      BorderBrush="#FF2A3B5C" BorderThickness="1" VerticalAlignment="Center">
                <TextBlock x:Name="Tick" Text="&#xE73E;" FontFamily="Segoe MDL2 Assets" FontSize="10"
                           Foreground="#FFFFFFFF" HorizontalAlignment="Center" VerticalAlignment="Center"
                           Visibility="Collapsed"/>
              </Border>
              <ContentPresenter Margin="7,0,0,0" VerticalAlignment="Center" RecognizesAccessKey="True"/>
            </StackPanel>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Tick" Property="Visibility" Value="Visible"/>
                <Setter TargetName="Box" Property="Background" Value="#FF3D63D6"/>
                <Setter TargetName="Box" Property="BorderBrush" Value="#FF3D63D6"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Box" Property="BorderBrush" Value="#FF5177E8"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.45"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ListBox">
      <Setter Property="Background" Value="#FF0F1622"/>
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
      <Setter Property="BorderBrush" Value="#FF1F2A40"/>
    </Style>
    <Style TargetType="ListBoxItem">
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ListBoxItem">
            <Border x:Name="Bd" Background="Transparent" CornerRadius="6" Padding="6,3" Margin="2,1">
              <ContentPresenter/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF182238"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="#FF1B2A47"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ProgressBar">
      <Setter Property="Height" Value="6"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Background" Value="#FF1B2436"/>
      <Setter Property="Foreground" Value="#FF3D63D6"/>
    </Style>
  </Window.Resources>
'@

$MainXaml += @'
  <DockPanel>
    <Border DockPanel.Dock="Bottom" Background="#FF0E1420" BorderBrush="#FF1C2537" BorderThickness="0,1,0,0" Padding="12,6">
      <DockPanel>
        <ProgressBar x:Name="PgStatus" DockPanel.Dock="Right" Width="170" Height="6" IsIndeterminate="True"
                     Visibility="Collapsed" Margin="10,0,0,0" VerticalAlignment="Center"/>
        <Button x:Name="BtnCancelJob" DockPanel.Dock="Right" Content="Stop operation" IsEnabled="False"
                Margin="12,0,6,0" Padding="10,3" FontSize="11"/>
        <TextBlock x:Name="TxtBgElapsed" DockPanel.Dock="Right" Text="00:00" Margin="14,0,0,0"
                   VerticalAlignment="Center" Foreground="#FF8A94A8" FontSize="11"/>
        <TextBlock x:Name="TxtBgState" Text="Ready" VerticalAlignment="Center" Foreground="#FF8A94A8" FontSize="11"/>
      </DockPanel>
    </Border>
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="232"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <Border Grid.Column="0" Background="#FF0E1420" BorderBrush="#FF1C2537" BorderThickness="0,0,1,0">
        <DockPanel Margin="10,0,10,0">
          <StackPanel DockPanel.Dock="Top">
            <StackPanel Orientation="Horizontal" Margin="6,14,6,16">
              <Border Width="34" Height="34" CornerRadius="9">
                <Border.Background>
                  <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                    <GradientStop Color="#FF4F7CFF" Offset="0"/>
                    <GradientStop Color="#FF8B5CF6" Offset="1"/>
                  </LinearGradientBrush>
                </Border.Background>
                <TextBlock Text="S" FontWeight="Bold" FontSize="17" Foreground="#FFFFFFFF"
                           HorizontalAlignment="Center" VerticalAlignment="Center"/>
              </Border>
              <StackPanel Margin="10,0,0,0" VerticalAlignment="Center">
                <TextBlock Text="STweak" FontSize="16" FontWeight="Bold"/>
                <TextBlock Text="System Toolkit" FontSize="10" Foreground="#FF8A94A8"/>
              </StackPanel>
            </StackPanel>
            <Border Height="1" Background="#FF1C2537" Margin="6,0,6,10"/>
            <Button x:Name="NavHome" Style="{StaticResource NavButton}">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="&#xE80F;" FontFamily="Segoe MDL2 Assets" FontSize="15" Width="26" VerticalAlignment="Center"/>
                <TextBlock Text="Home" FontSize="12.5" VerticalAlignment="Center"/>
              </StackPanel>
            </Button>
            <Button x:Name="NavApps" Style="{StaticResource NavButton}">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="&#xE71D;" FontFamily="Segoe MDL2 Assets" FontSize="15" Width="26" VerticalAlignment="Center"/>
                <TextBlock Text="App Manager" FontSize="12.5" VerticalAlignment="Center"/>
              </StackPanel>
            </Button>
            <Button x:Name="NavTweaks" Style="{StaticResource NavButton}">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="&#xE713;" FontFamily="Segoe MDL2 Assets" FontSize="15" Width="26" VerticalAlignment="Center"/>
                <TextBlock Text="System Tweaks" FontSize="12.5" VerticalAlignment="Center"/>
              </StackPanel>
            </Button>
            <Button x:Name="NavUninstall" Style="{StaticResource NavButton}">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="&#xE74D;" FontFamily="Segoe MDL2 Assets" FontSize="15" Width="26" VerticalAlignment="Center"/>
                <TextBlock Text="Deep Uninstall" FontSize="12.5" VerticalAlignment="Center"/>
              </StackPanel>
            </Button>
            <Button x:Name="NavCleanup" Style="{StaticResource NavButton}">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="&#xE72C;" FontFamily="Segoe MDL2 Assets" FontSize="15" Width="26" VerticalAlignment="Center"/>
                <TextBlock Text="Smart Cleaner" FontSize="12.5" VerticalAlignment="Center"/>
              </StackPanel>
            </Button>
            <Button x:Name="NavBloatware" Style="{StaticResource NavButton}">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="&#xE7B8;" FontFamily="Segoe MDL2 Assets" FontSize="15" Width="26" VerticalAlignment="Center"/>
                <TextBlock Text="Bloatware (AppX)" FontSize="12.5" VerticalAlignment="Center"/>
              </StackPanel>
            </Button>
            <Button x:Name="NavSecurity" Style="{StaticResource NavButton}">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="&#xE72E;" FontFamily="Segoe MDL2 Assets" FontSize="15" Width="26" VerticalAlignment="Center"/>
                <TextBlock Text="Security" FontSize="12.5" VerticalAlignment="Center"/>
              </StackPanel>
            </Button>
            <Button x:Name="NavHistory" Style="{StaticResource NavButton}">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="&#xE81C;" FontFamily="Segoe MDL2 Assets" FontSize="15" Width="26" VerticalAlignment="Center"/>
                <TextBlock Text="Safe Restore" FontSize="12.5" VerticalAlignment="Center"/>
              </StackPanel>
            </Button>
            <Button x:Name="NavQuarantine" Style="{StaticResource NavButton}">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="&#xE8B7;" FontFamily="Segoe MDL2 Assets" FontSize="15" Width="26" VerticalAlignment="Center"/>
                <TextBlock Text="Quarantine" FontSize="12.5" VerticalAlignment="Center"/>
              </StackPanel>
            </Button>
            <Button x:Name="NavLog" Style="{StaticResource NavButton}">
              <StackPanel Orientation="Horizontal">
                <TextBlock Text="&#xE7C3;" FontFamily="Segoe MDL2 Assets" FontSize="15" Width="26" VerticalAlignment="Center"/>
                <TextBlock Text="Activity Log" FontSize="12.5" VerticalAlignment="Center"/>
              </StackPanel>
            </Button>
          </StackPanel>
          <StackPanel DockPanel.Dock="Bottom">
            <Border Height="1" Background="#FF1C2537" Margin="6,10,6,8"/>
            <TextBlock Text="STweak v2.0 - runs as Administrator" FontSize="10" Foreground="#FF5C6A85"
                       Margin="6,0,6,10"/>
          </StackPanel>
          <Grid/>
        </DockPanel>
      </Border>
      <Grid x:Name="PageHost" Grid.Column="1" Background="#FF0B0F17">
        <Grid x:Name="PageHome" Margin="18,16,18,12">
'@

$MainXaml += @'
          <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel>
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel>
                  <TextBlock x:Name="TxtGreeting" Text="Welcome" FontSize="24" FontWeight="Bold"/>
                  <TextBlock x:Name="TxtHomeSub" Text="Here is your system at a glance." FontSize="12"
                             Foreground="#FF8A94A8" Margin="0,4,0,0"/>
                </StackPanel>
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Top" Margin="10,2,0,0">
                  <TextBlock x:Name="TxtHomeDate" Text="" FontSize="11.5" Foreground="#FF8A94A8"
                             VerticalAlignment="Center" Margin="0,0,10,0"/>
                  <Border Width="32" Height="32" CornerRadius="8" Background="#FF1B2436">
                    <TextBlock Text="&#xE706;" FontFamily="Segoe MDL2 Assets" FontSize="15" Foreground="#FFFFC66D"
                               HorizontalAlignment="Center" VerticalAlignment="Center"/>
                  </Border>
                </StackPanel>
              </Grid>
              <Grid Margin="0,16,0,0">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="380"/>
                </Grid.ColumnDefinitions>
                <Border CornerRadius="14" Background="#FF121A29" BorderBrush="#FF1F2A40" BorderThickness="1" Padding="22">
                  <Grid>
                    <Grid.ColumnDefinitions>
                      <ColumnDefinition Width="Auto"/>
                      <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    <Border x:Name="BrdHealthShield" Width="92" Height="92" CornerRadius="46" Background="#FF0F2418"
                            BorderBrush="#FF1F5133" BorderThickness="2" VerticalAlignment="Center">
                      <Border.Effect>
                        <DropShadowEffect Color="#FF34D399" BlurRadius="30" ShadowDepth="0" Opacity="0.45"/>
                      </Border.Effect>
                      <TextBlock x:Name="TxtHealthIcon" Text="&#xE72E;" FontFamily="Segoe MDL2 Assets" FontSize="38" Foreground="#FF4ADE80"
                                 HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <StackPanel Grid.Column="1" Margin="20,0,0,0" VerticalAlignment="Center">
                      <TextBlock x:Name="TxtHealthTitle" Text="System check" FontSize="21" FontWeight="Bold"
                                 Foreground="#FF4ADE80"/>
                      <TextBlock x:Name="TxtHealthSub" Text="Checking your PC..." Foreground="#FF8A94A8"
                                 TextWrapping="Wrap" Margin="0,6,0,0"/>
                      <StackPanel Orientation="Horizontal" Margin="0,16,0,0">
                        <Button x:Name="BtnHomeRunCleaner" Content="Run Smart Cleaner" Style="{StaticResource AccentButton}"/>
                        <Button x:Name="BtnHomeDetails" Content="View Details" Style="{StaticResource GhostButton}"/>
                      </StackPanel>
                    </StackPanel>
                  </Grid>
                </Border>
                <Border Grid.Column="1" Margin="16,0,0,0" CornerRadius="14" Background="#FF121A29"
                        BorderBrush="#FF1F2A40" BorderThickness="1" Padding="16">
                  <StackPanel>
                    <TextBlock Text="System Monitor" FontSize="13.5" FontWeight="Bold" Margin="0,0,0,8"/>
                    <Grid Margin="0,5,0,5">
                      <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="14"/>
                        <ColumnDefinition Width="62"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="42"/>
                        <ColumnDefinition Width="84"/>
                      </Grid.ColumnDefinitions>
                      <Ellipse Width="8" Height="8" Fill="#FF6B92FF" VerticalAlignment="Center"/>
                      <TextBlock Grid.Column="1" Text="CPU" Foreground="#FF8A94A8" VerticalAlignment="Center"/>
                      <ProgressBar x:Name="PgStatCpu" Grid.Column="2" Height="6" Value="0" Foreground="#FF6B92FF"
                                   VerticalAlignment="Center" Margin="0,0,10,0"/>
                      <TextBlock x:Name="TxtStatCpu" Grid.Column="3" Text="--" VerticalAlignment="Center"/>
                      <Border Grid.Column="4" Width="84" Height="26" CornerRadius="6" Background="#FF0F1622" ClipToBounds="True">
                        <Canvas Width="84" Height="24">
                          <Polyline x:Name="SpCpu" Stroke="#FF6B92FF" StrokeThickness="1.5"/>
                        </Canvas>
                      </Border>
                    </Grid>
                    <Grid Margin="0,5,0,5">
                      <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="14"/>
                        <ColumnDefinition Width="62"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="42"/>
                        <ColumnDefinition Width="84"/>
                      </Grid.ColumnDefinitions>
                      <Ellipse Width="8" Height="8" Fill="#FFB57BFF" VerticalAlignment="Center"/>
                      <TextBlock Grid.Column="1" Text="Memory" Foreground="#FF8A94A8" VerticalAlignment="Center"/>
                      <ProgressBar x:Name="PgStatRam" Grid.Column="2" Height="6" Value="0" Foreground="#FFB57BFF"
                                   VerticalAlignment="Center" Margin="0,0,10,0"/>
                      <TextBlock x:Name="TxtStatRam" Grid.Column="3" Text="--" VerticalAlignment="Center"/>
                      <Border Grid.Column="4" Width="84" Height="26" CornerRadius="6" Background="#FF0F1622" ClipToBounds="True">
                        <Canvas Width="84" Height="24">
                          <Polyline x:Name="SpRam" Stroke="#FFB57BFF" StrokeThickness="1.5"/>
                        </Canvas>
                      </Border>
                    </Grid>
                    <Grid Margin="0,5,0,5">
                      <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="14"/>
                        <ColumnDefinition Width="62"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="42"/>
                        <ColumnDefinition Width="84"/>
                      </Grid.ColumnDefinitions>
                      <Ellipse Width="8" Height="8" Fill="#FF34D399" VerticalAlignment="Center"/>
                      <TextBlock Grid.Column="1" Text="Disk C:" Foreground="#FF8A94A8" VerticalAlignment="Center"/>
                      <ProgressBar x:Name="PgStatDisk" Grid.Column="2" Height="6" Value="0" Foreground="#FF34D399"
                                   VerticalAlignment="Center" Margin="0,0,10,0"/>
                      <TextBlock x:Name="TxtStatDisk" Grid.Column="3" Text="--" VerticalAlignment="Center"/>
                      <Border Grid.Column="4" Width="84" Height="26" CornerRadius="6" Background="#FF0F1622" ClipToBounds="True">
                        <Canvas Width="84" Height="24">
                          <Polyline x:Name="SpDisk" Stroke="#FF34D399" StrokeThickness="1.5"/>
                        </Canvas>
                      </Border>
                    </Grid>
                  </StackPanel>
                </Border>
              </Grid>
              <TextBlock Text="Quick Actions" FontSize="13.5" FontWeight="Bold" Margin="0,18,0,8"/>
              <UniformGrid Columns="6">
                <Button x:Name="BtnQuickClean" Style="{StaticResource CardButton}">
                  <StackPanel>
                    <Border Width="36" Height="36" CornerRadius="10" Background="#FF15243D" HorizontalAlignment="Left">
                      <TextBlock Text="&#xE72C;" FontFamily="Segoe MDL2 Assets" FontSize="16" Foreground="#FF6B92FF"
                                 HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <TextBlock Text="Smart Cleaner" FontWeight="Bold" FontSize="13" Margin="0,10,0,2"/>
                    <TextBlock Text="Free up disk space" Foreground="#FF8A94A8" FontSize="10.5" TextWrapping="Wrap" MinHeight="28"/>
                    <TextBlock Text="&#xE76C;" FontFamily="Segoe MDL2 Assets" FontSize="11" Foreground="#FF6B92FF" Margin="0,8,0,0"/>
                  </StackPanel>
                </Button>
                <Button x:Name="BtnQuickApps" Style="{StaticResource CardButton}">
                  <StackPanel>
                    <Border Width="36" Height="36" CornerRadius="10" Background="#FF231B3D" HorizontalAlignment="Left">
                      <TextBlock Text="&#xE71D;" FontFamily="Segoe MDL2 Assets" FontSize="16" Foreground="#FFB57BFF"
                                 HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <TextBlock Text="App Manager" FontWeight="Bold" FontSize="13" Margin="0,10,0,2"/>
                    <TextBlock Text="Install and update apps" Foreground="#FF8A94A8" FontSize="10.5" TextWrapping="Wrap" MinHeight="28"/>
                    <TextBlock Text="&#xE76C;" FontFamily="Segoe MDL2 Assets" FontSize="11" Foreground="#FFB57BFF" Margin="0,8,0,0"/>
                  </StackPanel>
                </Button>
                <Button x:Name="BtnQuickTweaks" Style="{StaticResource CardButton}">
                  <StackPanel>
                    <Border Width="36" Height="36" CornerRadius="10" Background="#FF14301F" HorizontalAlignment="Left">
                      <TextBlock Text="&#xE713;" FontFamily="Segoe MDL2 Assets" FontSize="16" Foreground="#FF4ADE80"
                                 HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <TextBlock Text="System Tweaks" FontWeight="Bold" FontSize="13" Margin="0,10,0,2"/>
                    <TextBlock Text="Tune Windows your way" Foreground="#FF8A94A8" FontSize="10.5" TextWrapping="Wrap" MinHeight="28"/>
                    <TextBlock Text="&#xE76C;" FontFamily="Segoe MDL2 Assets" FontSize="11" Foreground="#FF4ADE80" Margin="0,8,0,0"/>
                  </StackPanel>
                </Button>
                <Button x:Name="BtnQuickUninstall" Style="{StaticResource CardButton}">
                  <StackPanel>
                    <Border Width="36" Height="36" CornerRadius="10" Background="#FF331B26" HorizontalAlignment="Left">
                      <TextBlock Text="&#xE74D;" FontFamily="Segoe MDL2 Assets" FontSize="16" Foreground="#FFF871A0"
                                 HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <TextBlock Text="Deep Uninstall" FontWeight="Bold" FontSize="13" Margin="0,10,0,2"/>
                    <TextBlock Text="Remove apps completely" Foreground="#FF8A94A8" FontSize="10.5" TextWrapping="Wrap" MinHeight="28"/>
                    <TextBlock Text="&#xE76C;" FontFamily="Segoe MDL2 Assets" FontSize="11" Foreground="#FFF871A0" Margin="0,8,0,0"/>
                  </StackPanel>
                </Button>
                <Button x:Name="BtnQuickHistory" Style="{StaticResource CardButton}">
                  <StackPanel>
                    <Border Width="36" Height="36" CornerRadius="10" Background="#FF332A15" HorizontalAlignment="Left">
                      <TextBlock Text="&#xE81C;" FontFamily="Segoe MDL2 Assets" FontSize="16" Foreground="#FFFBBF24"
                                 HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <TextBlock Text="Safe Restore" FontWeight="Bold" FontSize="13" Margin="0,10,0,2"/>
                    <TextBlock Text="Undo tweaks anytime" Foreground="#FF8A94A8" FontSize="10.5" TextWrapping="Wrap" MinHeight="28"/>
                    <TextBlock Text="&#xE76C;" FontFamily="Segoe MDL2 Assets" FontSize="11" Foreground="#FFFBBF24" Margin="0,8,0,0"/>
                  </StackPanel>
                </Button>
                <Button x:Name="BtnQuickSecurity" Style="{StaticResource CardButton}" Margin="0">
                  <StackPanel>
                    <Border Width="36" Height="36" CornerRadius="10" Background="#FF0F2B33" HorizontalAlignment="Left">
                      <TextBlock Text="&#xE72E;" FontFamily="Segoe MDL2 Assets" FontSize="16" Foreground="#FF2DD4BF"
                                 HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <TextBlock Text="Security" FontWeight="Bold" FontSize="13" Margin="0,10,0,2"/>
                    <TextBlock Text="Defender and firewall" Foreground="#FF8A94A8" FontSize="10.5" TextWrapping="Wrap" MinHeight="28"/>
                    <TextBlock Text="&#xE76C;" FontFamily="Segoe MDL2 Assets" FontSize="11" Foreground="#FF2DD4BF" Margin="0,8,0,0"/>
                  </StackPanel>
                </Button>
              </UniformGrid>
              <Border Margin="0,18,0,10" CornerRadius="14" BorderBrush="#FF2A3B5C" BorderThickness="1" Padding="20">
                <Border.Background>
                  <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                    <GradientStop Color="#FF17224A" Offset="0"/>
                    <GradientStop Color="#FF2A1B4A" Offset="1"/>
                  </LinearGradientBrush>
                </Border.Background>
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <StackPanel>
                    <TextBlock Text="All tools. One place." FontSize="16" FontWeight="Bold"/>
                    <TextBlock x:Name="TxtHomeTagline" Text="Tweaks, apps, cleanup and deep uninstall - all in one window."
                               Foreground="#FFAAB4C8" Margin="0,6,0,0"/>
                  </StackPanel>
                  <Button x:Name="BtnBannerTweaks" Grid.Column="1" Content="Open System Tweaks"
                          Style="{StaticResource AccentButton}" VerticalAlignment="Center" Margin="14,0,0,0"/>
                </Grid>
              </Border>
            </StackPanel>
          </ScrollViewer>
        </Grid>
'@

$MainXaml += @'
        <Grid x:Name="PageApps" Visibility="Collapsed" Margin="14,14,14,10">
          <DockPanel Margin="6">
            <StackPanel DockPanel.Dock="Top" Margin="0,0,0,2">
              <TextBlock Text="App Manager" FontSize="19" FontWeight="Bold"/>
              <TextBlock Text="Install, update and track apps with winget." Foreground="#FF8A94A8" FontSize="11.5" Margin="0,3,0,0"/>
            </StackPanel>
            <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,10,0,0">
              <TextBlock Text="Search:" VerticalAlignment="Center" Margin="0,0,6,0"/>
              <TextBox x:Name="TxtAppSearch" Width="220"/>
              <TextBlock Text="Category:" Margin="14,0,6,0" VerticalAlignment="Center"/>
              <ComboBox x:Name="CmbAppCategory" Width="170" Margin="0,0,6,0"/>
              <CheckBox x:Name="ChkAppsInstalledOnly" Content="Show only installed" VerticalAlignment="Center" Margin="8,0,8,0"/>
              <Button x:Name="BtnRefreshWinget" Content="Refresh installed status"/>
              <Button x:Name="BtnInstallSelected" Content="Install selected"/>
            </StackPanel>
            <Border DockPanel.Dock="Bottom" BorderBrush="#FF1F2A40" BorderThickness="1" Background="#FF121A29" Margin="0,8,0,0" Padding="6">
              <DockPanel>
                <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,6">
                  <Button x:Name="BtnScanUpgrades" Content="Check for app updates"/>
                  <Button x:Name="BtnUpgradeSelected" Content="Upgrade selected"/>
                  <TextBlock x:Name="TxtUpgradeInfo" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="#FF8A94A8"/>
                </StackPanel>
                <Border BorderBrush="#FF1F2A40" BorderThickness="1" Background="#FF0F1622" Height="150">
                  <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel x:Name="PnlUpgrades" Margin="6"/>
                  </ScrollViewer>
                </Border>
              </DockPanel>
            </Border>
            <Border BorderBrush="#FF1F2A40" BorderThickness="1" Background="#FF121A29" Margin="0,8,0,0">
              <ScrollViewer VerticalScrollBarVisibility="Auto">
                <StackPanel x:Name="PnlApps" Margin="6"/>
              </ScrollViewer>
            </Border>
          </DockPanel>
        </Grid>
        <Grid x:Name="PageTweaks" Visibility="Collapsed" Margin="14,14,14,10">
          <DockPanel Margin="6">
            <StackPanel DockPanel.Dock="Top" Margin="0,0,0,2">
              <TextBlock Text="System Tweaks" FontSize="19" FontWeight="Bold"/>
              <TextBlock Text="Tune Windows with reversible tweaks - apply, revert, and re-check anytime." Foreground="#FF8A94A8" FontSize="11.5" Margin="0,3,0,0"/>
            </StackPanel>
            <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,10,0,0">
              <TextBlock Text="Preset:" VerticalAlignment="Center" Margin="0,0,6,0"/>
              <ComboBox x:Name="CmbPreset" Width="150" Margin="0,0,6,0"/>
              <Button x:Name="BtnApplyPreset" Content="Apply preset"/>
              <TextBlock Text="Search:" Margin="14,0,6,0" VerticalAlignment="Center"/>
              <TextBox x:Name="TxtTweakSearch" Width="170"/>
              <TextBlock Text="Category:" Margin="14,0,6,0" VerticalAlignment="Center"/>
              <ComboBox x:Name="CmbTweakCategory" Width="150" Margin="0,0,6,0"/>
              <Button x:Name="BtnCheckTweaks" Content="Re-check states"/>
            </StackPanel>
            <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" Margin="0,8,0,0">
              <Button x:Name="BtnApplyTweaks" Content="Apply selected"/>
              <Button x:Name="BtnRevertTweaks" Content="Revert selected"/>
              <TextBlock x:Name="TxtTweakInfo" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="#FF8A94A8"/>
            </StackPanel>
            <Border BorderBrush="#FF1F2A40" BorderThickness="1" Background="#FF121A29" Margin="0,8,0,0">
              <ScrollViewer VerticalScrollBarVisibility="Auto">
                <StackPanel x:Name="PnlTweaks" Margin="6"/>
              </ScrollViewer>
            </Border>
          </DockPanel>
        </Grid>
        <Grid x:Name="PageUninstall" Visibility="Collapsed" Margin="14,14,14,10">
          <DockPanel Margin="6">
            <StackPanel DockPanel.Dock="Top" Margin="0,0,0,2">
              <TextBlock Text="Deep Uninstall" FontSize="19" FontWeight="Bold"/>
              <TextBlock Text="Remove a program, scan for leftovers, and review them before anything is touched." Foreground="#FF8A94A8" FontSize="11.5" Margin="0,3,0,0"/>
            </StackPanel>
            <TextBlock DockPanel.Dock="Top" TextWrapping="Wrap" Foreground="#FF8A94A8" Margin="0,8,0,0"
                       Text="Pick a program from the list (or type a name), then run the deep scan. The optional first step runs the program's own uninstaller, then STweak scans for everything it left behind and shows a review list."/>
            <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,8,0,0">
              <TextBlock Text="Filter:" VerticalAlignment="Center" Margin="0,0,6,0"/>
              <TextBox x:Name="TxtUninstallFilter" Width="200" Margin="0,0,6,0"/>
              <Button x:Name="BtnLoadPrograms" Content="Load installed programs"/>
              <TextBlock Text="or type a name:" Margin="14,0,6,0" VerticalAlignment="Center"/>
              <TextBox x:Name="TxtManualAppName" Width="190" Margin="0,0,6,0"/>
              <Button x:Name="BtnScanManual" Content="Deep scan"/>
            </StackPanel>
            <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" Margin="0,8,0,0">
              <CheckBox x:Name="ChkRunUninstaller" Content="Run the official uninstaller first (recommended)"
                        IsChecked="True" VerticalAlignment="Center"/>
              <Button x:Name="BtnDeepScan" Content="Deep scan selected program" Margin="16,0,6,0"/>
              <TextBlock x:Name="TxtUninstallInfo" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="#FF8A94A8"/>
            </StackPanel>
            <ListBox x:Name="LstUninstallPrograms" Margin="0,8,0,0"/>
          </DockPanel>
        </Grid>
        <Grid x:Name="PageCleanup" Visibility="Collapsed" Margin="14,14,14,10">
          <DockPanel Margin="6">
            <StackPanel DockPanel.Dock="Top" Margin="0,0,0,2">
              <TextBlock Text="Smart Cleaner" FontSize="19" FontWeight="Bold"/>
              <TextBlock Text="Free up disk space safely - analyze first, then clean the selected targets." Foreground="#FF8A94A8" FontSize="11.5" Margin="0,3,0,0"/>
            </StackPanel>
            <TextBlock DockPanel.Dock="Top" TextWrapping="Wrap" Foreground="#FF8A94A8" Margin="0,8,0,0"
                       Text="Select what to clean, click Analyze to see the sizes, then Clean. Active browser windows may lock some cache files - close them for best results."/>
            <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" Margin="0,8,0,0">
              <Button x:Name="BtnAnalyzeCleanup" Content="Analyze sizes"/>
              <Button x:Name="BtnRunCleanup" Content="Clean selected"/>
              <TextBlock x:Name="TxtCleanupInfo" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="#FF8A94A8"/>
            </StackPanel>
            <ScrollViewer VerticalScrollBarVisibility="Auto" Margin="0,8,0,0">
              <StackPanel x:Name="PnlCleanup">
                <StackPanel Orientation="Horizontal" Margin="0,3,0,3"><CheckBox x:Name="ChkClnUserTemp" Content="User temp files (%TEMP%)"/><TextBlock x:Name="TxtClnUserTemp" Margin="12,0,0,0" Foreground="#FF8A94A8"/></StackPanel>
                <StackPanel Orientation="Horizontal" Margin="0,3,0,3"><CheckBox x:Name="ChkClnWindowsTemp" Content="Windows temp (C:\Windows\Temp)"/><TextBlock x:Name="TxtClnWindowsTemp" Margin="12,0,0,0" Foreground="#FF8A94A8"/></StackPanel>
                <StackPanel Orientation="Horizontal" Margin="0,3,0,3"><CheckBox x:Name="ChkClnUpdateCache" Content="Windows Update cache (SoftwareDistribution\Download)"/><TextBlock x:Name="TxtClnUpdateCache" Margin="12,0,0,0" Foreground="#FF8A94A8"/></StackPanel>
                <StackPanel Orientation="Horizontal" Margin="0,3,0,3"><CheckBox x:Name="ChkClnDeliveryOpt" Content="Delivery Optimization cache"/><TextBlock x:Name="TxtClnDeliveryOpt" Margin="12,0,0,0" Foreground="#FF8A94A8"/></StackPanel>
                <StackPanel Orientation="Horizontal" Margin="0,3,0,3"><CheckBox x:Name="ChkClnWerReports" Content="Windows Error Reporting archives"/><TextBlock x:Name="TxtClnWerReports" Margin="12,0,0,0" Foreground="#FF8A94A8"/></StackPanel>
                <StackPanel Orientation="Horizontal" Margin="0,3,0,3"><CheckBox x:Name="ChkClnThumbCache" Content="Explorer thumbnail cache"/><TextBlock x:Name="TxtClnThumbCache" Margin="12,0,0,0" Foreground="#FF8A94A8"/></StackPanel>
                <StackPanel Orientation="Horizontal" Margin="0,3,0,3"><CheckBox x:Name="ChkClnINetCache" Content="Internet cache (INetCache)"/><TextBlock x:Name="TxtClnINetCache" Margin="12,0,0,0" Foreground="#FF8A94A8"/></StackPanel>
                <StackPanel Orientation="Horizontal" Margin="0,3,0,3"><CheckBox x:Name="ChkClnD3DSCache" Content="Direct3D shader cache (D3DSCache)"/><TextBlock x:Name="TxtClnD3DSCache" Margin="12,0,0,0" Foreground="#FF8A94A8"/></StackPanel>
                <StackPanel Orientation="Horizontal" Margin="0,3,0,3"><CheckBox x:Name="ChkClnRecycleBin" Content="Recycle Bin (all drives)"/><TextBlock x:Name="TxtClnRecycleBin" Margin="12,0,0,0" Foreground="#FF8A94A8"/></StackPanel>
              </StackPanel>
            </ScrollViewer>
          </DockPanel>
        </Grid>
        <Grid x:Name="PageBloatware" Visibility="Collapsed" Margin="14,14,14,10">
          <DockPanel Margin="6">
            <StackPanel DockPanel.Dock="Top" Margin="0,0,0,2">
              <TextBlock Text="Bloatware (AppX)" FontSize="19" FontWeight="Bold"/>
              <TextBlock Text="Remove preinstalled AppX packages - per user, or provisioned for all users." Foreground="#FF8A94A8" FontSize="11.5" Margin="0,3,0,0"/>
            </StackPanel>
            <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,10,0,0">
              <Button x:Name="BtnLoadAppx" Content="Load AppX packages"/>
              <CheckBox x:Name="ChkAppxAllUsers" Content="Also remove for all users (provisioned)" VerticalAlignment="Center" Margin="12,0,10,0"/>
              <Button x:Name="BtnRemoveAppx" Content="Remove selected"/>
              <TextBlock x:Name="TxtAppxInfo" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="#FF8A94A8"/>
            </StackPanel>
            <ListBox x:Name="LstAppx" Margin="0,8,0,0" SelectionMode="Extended"/>
          </DockPanel>
        </Grid>
        <Grid x:Name="PageSecurity" Visibility="Collapsed" Margin="14,14,14,10">
          <DockPanel Margin="6">
            <StackPanel DockPanel.Dock="Top" Margin="0,0,0,2">
              <TextBlock Text="Security" FontSize="19" FontWeight="Bold"/>
              <TextBlock Text="Defender state, signature updates and scans from one place." Foreground="#FF8A94A8" FontSize="11.5" Margin="0,3,0,0"/>
            </StackPanel>
            <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,10,0,0">
              <Button x:Name="BtnRefreshSecurity" Content="Check status"/>
              <Button x:Name="BtnSecOpenDefender" Content="Open Windows Security"/>
              <Button x:Name="BtnSecUpdateDefs" Content="Update signatures"/>
              <Button x:Name="BtnSecQuickScan" Content="Quick scan"/>
              <Button x:Name="BtnSecFullScan" Content="Full scan"/>
              <TextBlock x:Name="TxtSecInfo" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="#FF8A94A8"/>
            </StackPanel>
            <TextBox x:Name="TxtSecReport" IsReadOnly="True" AcceptsReturn="True" TextWrapping="Wrap"
                     VerticalScrollBarVisibility="Auto" FontFamily="Consolas" Margin="0,8,0,0"
                     Background="#FF0F1622" BorderBrush="#FF1F2A40"/>
          </DockPanel>
        </Grid>
        <Grid x:Name="PageHistory" Visibility="Collapsed" Margin="14,14,14,10">
          <DockPanel Margin="6">
            <StackPanel DockPanel.Dock="Top" Margin="0,0,0,2">
              <TextBlock Text="Safe Restore" FontSize="19" FontWeight="Bold"/>
              <TextBlock Text="Revert any tweak STweak applied, and manage apps it installed." Foreground="#FF8A94A8" FontSize="11.5" Margin="0,3,0,0"/>
            </StackPanel>
            <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,10,0,0">
              <Button x:Name="BtnRefreshHistory" Content="Refresh"/>
              <Button x:Name="BtnUndoAllTweaks" Content="Undo all applied tweaks"/>
              <TextBlock x:Name="TxtHistoryInfo" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="#FF8A94A8"/>
            </StackPanel>
            <ScrollViewer VerticalScrollBarVisibility="Auto" Margin="0,8,0,0">
              <StackPanel>
                <TextBlock Text="Applied tweaks (revert individually)" FontWeight="Bold" Margin="0,0,0,6"/>
                <StackPanel x:Name="PnlHistoryTweaks"/>
                <TextBlock Text="Apps installed by STweak" FontWeight="Bold" Margin="0,14,0,6"/>
                <StackPanel x:Name="PnlHistoryApps"/>
              </StackPanel>
            </ScrollViewer>
          </DockPanel>
        </Grid>
        <Grid x:Name="PageQuarantine" Visibility="Collapsed" Margin="14,14,14,10">
          <DockPanel Margin="6">
            <StackPanel DockPanel.Dock="Top" Margin="0,0,0,2">
              <TextBlock Text="Quarantine" FontSize="19" FontWeight="Bold"/>
              <TextBlock Text="Leftover files kept by deep uninstall - restore or delete them permanently." Foreground="#FF8A94A8" FontSize="11.5" Margin="0,3,0,0"/>
            </StackPanel>
            <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,10,0,0">
              <Button x:Name="BtnRefreshQuarantine" Content="Refresh"/>
              <Button x:Name="BtnOpenQuarantineFolder" Content="Open quarantine folder"/>
              <TextBlock x:Name="TxtQuarantineInfo" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="#FF8A94A8"/>
            </StackPanel>
            <ScrollViewer VerticalScrollBarVisibility="Auto" Margin="0,8,0,0">
              <StackPanel x:Name="PnlQuarantine"/>
            </ScrollViewer>
          </DockPanel>
        </Grid>
        <Grid x:Name="PageLog" Visibility="Collapsed" Margin="14,14,14,10">
          <DockPanel Margin="6">
            <StackPanel DockPanel.Dock="Top" Margin="0,0,0,2">
              <TextBlock Text="Activity Log" FontSize="19" FontWeight="Bold"/>
              <TextBlock Text="What STweak did, and the live output of the current background job." Foreground="#FF8A94A8" FontSize="11.5" Margin="0,3,0,0"/>
            </StackPanel>
            <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,10,0,0">
              <Button x:Name="BtnOpenTextLog" Content="Open stweak.log"/>
              <Button x:Name="BtnOpenDataFolder" Content="Open data folder"/>
              <Button x:Name="BtnClearActivityLog" Content="Clear view"/>
            </StackPanel>
            <Grid Margin="0,8,0,0">
              <Grid.RowDefinitions>
                <RowDefinition Height="*"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>
              <TextBox x:Name="TxtActivityLog" Grid.Row="0" IsReadOnly="True" AcceptsReturn="True"
                       TextWrapping="NoWrap" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                       FontFamily="Consolas" Background="#FF0F1622" BorderBrush="#FF1F2A40"/>
              <DockPanel Grid.Row="1" Margin="0,8,0,0">
                <TextBlock DockPanel.Dock="Top" Text="Background operation output (live):" Foreground="#FF8A94A8" Margin="0,0,0,4"/>
                <TextBox x:Name="TxtBgLog" IsReadOnly="True" AcceptsReturn="True" TextWrapping="NoWrap"
                         VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                         FontFamily="Consolas" Background="#FF0F1622" BorderBrush="#FF1F2A40"/>
              </DockPanel>
            </Grid>
          </DockPanel>
        </Grid>
      </Grid>
    </Grid>
  </DockPanel>
</Window>
'@

[xml]$xamlMain = $MainXaml
$readerMain = New-Object System.Xml.XmlNodeReader $xamlMain
$script:Window = [System.Windows.Markup.XamlReader]::Load($readerMain)


$refNames = @(
    'PnlApps','TxtAppSearch','CmbAppCategory','ChkAppsInstalledOnly','BtnRefreshWinget',
    'BtnInstallSelected','BtnScanUpgrades','BtnUpgradeSelected','TxtUpgradeInfo','PnlUpgrades',
    'CmbPreset','BtnApplyPreset','TxtTweakSearch','CmbTweakCategory','BtnCheckTweaks','BtnApplyTweaks',
    'BtnRevertTweaks','TxtTweakInfo','PnlTweaks',
    'TxtUninstallFilter','BtnLoadPrograms','TxtManualAppName','BtnScanManual','ChkRunUninstaller',
    'BtnDeepScan','TxtUninstallInfo','LstUninstallPrograms',
    'BtnAnalyzeCleanup','BtnRunCleanup','TxtCleanupInfo','PnlCleanup',
    'ChkClnUserTemp','TxtClnUserTemp','ChkClnWindowsTemp','TxtClnWindowsTemp','ChkClnUpdateCache','TxtClnUpdateCache',
    'ChkClnDeliveryOpt','TxtClnDeliveryOpt','ChkClnWerReports','TxtClnWerReports','ChkClnThumbCache','TxtClnThumbCache',
    'ChkClnINetCache','TxtClnINetCache','ChkClnD3DSCache','TxtClnD3DSCache','ChkClnRecycleBin','TxtClnRecycleBin',
    'BtnLoadAppx','ChkAppxAllUsers','BtnRemoveAppx','TxtAppxInfo','LstAppx',
    'BtnRefreshSecurity','BtnSecOpenDefender','BtnSecUpdateDefs','BtnSecQuickScan','BtnSecFullScan','TxtSecInfo','TxtSecReport',
    'BtnRefreshHistory','BtnUndoAllTweaks','TxtHistoryInfo','PnlHistoryTweaks','PnlHistoryApps',
    'BtnRefreshQuarantine','BtnOpenQuarantineFolder','TxtQuarantineInfo','PnlQuarantine',
    'BtnOpenTextLog','BtnOpenDataFolder','BtnClearActivityLog','TxtActivityLog','TxtBgLog',
    'PgStatus','BtnCancelJob','TxtBgElapsed','TxtBgState',
    'NavHome','NavApps','NavTweaks','NavUninstall','NavCleanup','NavBloatware','NavSecurity','NavHistory','NavQuarantine','NavLog',
    'PageHome','PageApps','PageTweaks','PageUninstall','PageCleanup','PageBloatware','PageSecurity','PageHistory','PageQuarantine','PageLog',
    'TxtGreeting','TxtHomeSub','TxtHomeDate','TxtHealthTitle','TxtHealthSub','BtnHomeRunCleaner','BtnHomeDetails',
    'TxtStatCpu','TxtStatRam','TxtStatDisk','PgStatCpu','PgStatRam','PgStatDisk','SpCpu','SpRam','SpDisk',
    'BtnQuickClean','BtnQuickApps','BtnQuickTweaks','BtnQuickUninstall','BtnQuickHistory','BtnQuickSecurity',
    'TxtHomeTagline','BtnBannerTweaks','BrdHealthShield','TxtHealthIcon'
)
foreach ($n in $refNames) { Set-Variable -Name $n -Value $script:Window.FindName($n) -Scope Script }

$script:BrGreen = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF6DD58C'))
$script:BrGray  = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FFB0B0B0'))
$script:BrAmber = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FFFFC66D'))
$script:BrDim   = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF909090'))
$script:BrHealthGreenBg     = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF0F2418'))
$script:BrHealthGreenBorder = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF1F5133'))
$script:BrHealthAmberBg     = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF2A2410'))
$script:BrHealthAmberBorder = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF5C4A1F'))

function Write-Log {
    param([string]$Text)
    $stamp = (Get-Date).ToString('HH:mm:ss')
    if ($script:TxtActivityLog) {
        try {
            $script:TxtActivityLog.AppendText($stamp + '  ' + $Text + [Environment]::NewLine)
            $script:TxtActivityLog.ScrollToEnd()
        } catch { }
    }
    Write-FileLog $Text
}

function Set-Busy {
    param([bool]$Busy)
    if ($script:PgStatus) {
        if ($Busy) { $script:PgStatus.Visibility = 'Visible' } else { $script:PgStatus.Visibility = 'Collapsed' }
    }
    if ($script:BtnCancelJob) { $script:BtnCancelJob.IsEnabled = $Busy }
}

function SetCursorWait {
    param([bool]$On)
    if ($On) { [System.Windows.Input.Mouse]::OverrideCursor = [System.Windows.Input.Cursors]::Wait }
    else     { [System.Windows.Input.Mouse]::OverrideCursor = $null }
}

function Show-Info {
    param([string]$Text, [string]$Title = 'STweak')
    Enter-DialogScope
    try { [System.Windows.MessageBox]::Show($Text, $Title, 'OK', 'Information') | Out-Null }
    finally { Exit-DialogScope }
}

function Show-Err {
    param([string]$Text, [string]$Title = 'STweak')
    Enter-DialogScope
    try { [System.Windows.MessageBox]::Show($Text, $Title, 'OK', 'Error') | Out-Null }
    finally { Exit-DialogScope }
}

function Ask-YesNo {
    param([string]$Text, [string]$Title = 'STweak')
    Enter-DialogScope
    try { return ([System.Windows.MessageBox]::Show($Text, $Title, 'YesNo', 'Question') -eq 'Yes') }
    finally { Exit-DialogScope }
}

function Get-TweakStatusBrush {
    param([string]$Status)
    if ($Status -eq 'Applied')       { return $script:BrGreen }
    if ($Status -eq 'Partial')       { return $script:BrAmber }
    if ($Status -eq 'NotApplied')    { return $script:BrGray }
    return $script:BrDim
}

$ConfirmXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="STweak - Confirm" Width="780" Height="580"
        WindowStartupLocation="CenterOwner" Background="#FF0B0F17" Foreground="#FFE8ECF4">
  <Window.Resources>
    <Style TargetType="TextBlock">
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
    </Style>
    <Style TargetType="Button">
      <Setter Property="Background" Value="#FF1B2436"/>
      <Setter Property="Foreground" Value="#FFE8ECF4"/>
      <Setter Property="BorderBrush" Value="#FF2A3B5C"/>
      <Setter Property="Padding" Value="12,4"/>
    </Style>
  </Window.Resources>
  <DockPanel Margin="10">
    <StackPanel DockPanel.Dock="Top">
      <TextBlock x:Name="TxtCfTitle" FontSize="15" FontWeight="Bold" TextWrapping="Wrap"/>
      <TextBlock x:Name="TxtCfNotes" Margin="0,6,0,6" Foreground="#FFFFC66D" TextWrapping="Wrap"/>
    </StackPanel>
    <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,8,0,0">
      <Button x:Name="BtnCfOk" Content="Confirm" Padding="18,4" Margin="0,0,8,0" IsDefault="True"
              Background="#FF3D63D6" BorderBrush="#FF3D63D6"/>
      <Button x:Name="BtnCfCancel" Content="Cancel" Padding="18,4" IsCancel="True"/>
    </StackPanel>
    <TextBox x:Name="TxtCfLines" IsReadOnly="True" AcceptsReturn="True" TextWrapping="NoWrap"
             VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
             FontFamily="Consolas" Background="#FF0F1622" Foreground="#FFE8ECF4" BorderBrush="#FF1F2A40"/>
  </DockPanel>
</Window>
'@

$script:CfDlg = $null
$script:CfReturn = $false

function Initialize-ConfirmDialog {
    if ($script:CfDlg) { return }
    [xml]$xamlCf = $ConfirmXaml
    $dlg = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xamlCf))
    $script:CfDlg = $dlg
    $dlg.FindName('BtnCfOk').Add_Click({ $script:CfReturn = $true; $script:CfDlg.Close() })
    $dlg.FindName('BtnCfCancel').Add_Click({ $script:CfReturn = $false; $script:CfDlg.Close() })
}

function Show-ConfirmDialog {
    param([string]$Title, [string[]]$Lines, [string[]]$Notes = @())
    Initialize-ConfirmDialog
    $script:CfReturn = $false
    $script:CfDlg.FindName('TxtCfTitle').Text = $Title
    $script:CfDlg.FindName('TxtCfNotes').Text = ($Notes -join [Environment]::NewLine)
    $script:CfDlg.FindName('TxtCfLines').Text = ($Lines -join [Environment]::NewLine)
    if ($script:Window) { $script:CfDlg.Owner = $script:Window }
    Enter-DialogScope
    try { $script:CfDlg.ShowDialog() | Out-Null }
    finally { Exit-DialogScope }
    return $script:CfReturn
}

$script:TweakRows = @{}

function New-GroupHeader {
    param([string]$Text)
    $hdr = New-Object System.Windows.Controls.TextBlock
    $hdr.Text = $Text
    $hdr.FontWeight = 'Bold'
    $hdr.Foreground = $script:BrAmber
    $hdr.Margin = New-Object System.Windows.Thickness(2, 10, 2, 4)
    return $hdr
}

function Build-TweakRows {
    $script:PnlTweaks.Children.Clear()
    $script:TweakRows = @{}
    $q = [string]$script:TxtTweakSearch.Text
    $q = $q.Trim().ToLower()
    $cat = [string]$script:CmbTweakCategory.SelectedItem
    $groups = @{}
    $order = New-Object System.Collections.Generic.List[string]
    foreach ($t in $TweakCatalog) {
        if ($cat -and $cat -ne 'All' -and $t.Category -ne $cat) { continue }
        if ($q) {
            $hay = ($t.Name + ' ' + $t.Key + ' ' + $t.Category).ToLower()
            if (-not $hay.Contains($q)) { continue }
        }
        if (-not $groups.ContainsKey($t.Category)) {
            $groups[$t.Category] = New-Object System.Collections.Generic.List[object]
            [void]$order.Add($t.Category)
        }
        [void]$groups[$t.Category].Add($t)
    }
    foreach ($c in $order) {
        [void]$script:PnlTweaks.Children.Add((New-GroupHeader $c))
        foreach ($t in $groups[$c]) {
            $row = New-Object System.Windows.Controls.StackPanel
            $row.Orientation = 'Horizontal'
            $row.Margin = New-Object System.Windows.Thickness(6, 2, 6, 2)
            $cb = New-Object System.Windows.Controls.CheckBox
            $cb.MinWidth = 400
            $cb.Tag = $t.Key
            $cb.Content = $t.Name
            $st = New-Object System.Windows.Controls.TextBlock
            $st.Tag = ('st_' + $t.Key)
            $st.Margin = New-Object System.Windows.Thickness(10, 0, 10, 0)
            $st.Text = '...'
            $st.Foreground = $script:BrDim
            [void]$row.Children.Add($cb)
            [void]$row.Children.Add($st)
            if ($t.Note) {
                $note = New-Object System.Windows.Controls.TextBlock
                $note.Text = [string]$t.Note
                $note.Foreground = $script:BrDim
                $note.FontStyle = 'Italic'
                [void]$row.Children.Add($note)
            }
            [void]$script:PnlTweaks.Children.Add($row)
            $script:TweakRows[$t.Key] = @{ Check = $cb; Status = $st }
        }
    }
    $script:TxtTweakInfo.Text = ('Showing ' + $script:TweakRows.Count + ' of ' + $TweakCatalog.Count + ' tweaks.')
}

function Update-TweakStatusRow {
    param([string]$Key)
    $row = $script:TweakRows[$Key]
    if (-not $row) { return }
    $t = $TweakByKey[$Key]
    if (-not $t) { return }
    $st = 'Unknown'
    try { $st = [string](& $t.GetStatus) } catch { $st = 'Unknown' }
    if ($row.Status) {
        $row.Status.Text = $st
        $row.Status.Foreground = Get-TweakStatusBrush $st
    }
}

function Update-TweakInfoLine {
    $applied = 0
    foreach ($key in @($script:TweakRows.Keys)) {
        $row = $script:TweakRows[$key]
        if ($row -and $row.Status -and ($row.Status.Text -eq 'Applied')) { $applied++ }
    }
    $script:TxtTweakInfo.Text = ('Showing ' + $script:TweakRows.Count + ' of ' + $script:TweakCatalog.Count + ' tweaks.  Applied: ' + $applied + '.')
}

function Refresh-TweakStatuses {
    param([string[]]$Keys = $null)
    if ($Keys -and $Keys.Count -gt 0) {
        SetCursorWait $true
        try { foreach ($key in @($Keys)) { Update-TweakStatusRow -Key $key } } finally { SetCursorWait $false }
        Update-TweakInfoLine
        return
    }
    $all = @($script:TweakRows.Keys)
    if ($script:UiPumping -and ($all.Count -gt 14)) {
        $script:StatusKeys = $all
        $script:StatusIndex = 0
        if ($script:TxtTweakInfo) { $script:TxtTweakInfo.Text = ('Refreshing statuses...  ' + $all.Count + ' items') }
        $script:StatusTimer.Stop()
        $script:StatusTimer.Start()
        return
    }
    SetCursorWait $true
    try { foreach ($key in $all) { Update-TweakStatusRow -Key $key } } finally { SetCursorWait $false }
    Update-TweakInfoLine
}
function Get-SelectedTweakKeys {
    $sel = New-Object System.Collections.Generic.List[string]
    foreach ($key in @($script:TweakRows.Keys)) {
        $row = $script:TweakRows[$key]
        if ($row.Check -and $row.Check.IsChecked -eq $true) { [void]$sel.Add($key) }
    }
    return $sel.ToArray()
}

function Invoke-PostTweakFlags {
    param([bool]$ExplorerRestart, [bool]$SignOut)
    if ($ExplorerRestart) {
        if (Ask-YesNo 'Restart Windows Explorer now so the change applies immediately?' 'Restart Explorer') {
            try {
                Stop-Process -Name explorer -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
                Start-Process explorer.exe
            } catch { }
        }
    }
    if ($SignOut) { Show-Info 'Some of the applied changes need signing out and back in to fully take effect.' 'Sign out recommended' }
}

function Apply-TweaksSelected {
    $sel = @(Get-SelectedTweakKeys)
    if ($sel.Count -eq 0) { Show-Info 'No tweaks are selected.'; return }
    $planLines = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]
    $states = @{}
    $needExplorer = $false
    $needSignOut = $false
    foreach ($key in $sel) {
        $t = $TweakByKey[$key]
        try { $states[$key] = & $t.GetState } catch { $states[$key] = @{} }
        try {
            foreach ($ln in @(& $t.Plan $states[$key])) { [void]$planLines.Add('[' + $t.Name + ']  ' + [string]$ln) }
        } catch {
            [void]$planLines.Add('[' + $t.Name + ']  (could not build the plan: ' + $_.Exception.Message + ')')
        }
        if ($t.NeedsExplorerRestart) { $needExplorer = $true }
        if ($t.NeedsSignOut) { $needSignOut = $true }
        if ($t.Note) { [void]$notes.Add($t.Name + ': ' + $t.Note) }
    }
    [void]$notes.Add('Current values are captured first; you can revert any time from the History tab.')
    if (-not (Show-ConfirmDialog -Title ('Apply ' + $sel.Count + ' tweak(s)?') -Lines $planLines.ToArray() -Notes $notes.ToArray())) { return }

    SetCursorWait $true
    $ok = 0
    $fail = 0
    $fails = New-Object System.Collections.Generic.List[string]
    foreach ($key in $sel) {
        $t = $TweakByKey[$key]
        try {
            $extra = & $t.Apply
            Add-AppliedTweak -TweakKey $key -DisplayName $t.Name -State $states[$key]
            if ($extra) { Merge-AppliedTweakExtraState -TweakKey $key -Extra $extra }
            $ok++
            Write-Log ('Applied tweak: ' + $t.Name)
        } catch {
            $fail++
            [void]$fails.Add($t.Name + ': ' + $_.Exception.Message)
            Write-Log ('FAILED tweak: ' + $t.Name + '  -  ' + $_.Exception.Message)
        }
    }
    SetCursorWait $false
    Invoke-PostTweakFlags -ExplorerRestart $needExplorer -SignOut $needSignOut
    Refresh-TweakStatuses -Keys $sel
    $msg = 'Applied: ' + $ok + '    Failed: ' + $fail
    if ($fail -gt 0) {
        $msg = $msg + [Environment]::NewLine + [Environment]::NewLine + ($fails -join [Environment]::NewLine)
        Show-Err $msg 'Tweaks result'
    } else {
        Show-Info $msg 'Tweaks result'
    }
}

function Invoke-RevertTweakEntry {
    param($Entry)
    $key = [string]$Entry.key
    $t = $TweakByKey[$key]
    if (-not $t) { return @{ Ok = $false; Msg = ($key + ': unknown tweak (skipped)') } }
    try {
        & $t.Restore (ConvertTo-HashtableDeep $Entry.state)
        Remove-AppliedTweakEntry -TweakKey $key
        Write-Log ('Reverted tweak: ' + $t.Name)
        return @{ Ok = $true; Msg = $t.Name }
    } catch {
        Write-Log ('FAILED revert: ' + $t.Name + '  -  ' + $_.Exception.Message)
        return @{ Ok = $false; Msg = ($t.Name + ': ' + $_.Exception.Message) }
    }
}

function Revert-TweaksSelected {
    $sel = @(Get-SelectedTweakKeys)
    if ($sel.Count -eq 0) { Show-Info 'No tweaks are selected.'; return }
    $log = Get-ActionLog
    $entries = @()
    foreach ($e in $log.appliedTweaks) {
        if ($sel -contains [string]$e.key) { $entries += $e }
    }
    if ($entries.Count -eq 0) { Show-Info 'None of the selected tweaks are tracked as applied, so there is nothing to revert.'; return }
    $lines = @()
    foreach ($e in $entries) { $lines += ('REVERT: ' + [string]$e.name) }
    if (-not (Show-ConfirmDialog -Title ('Revert ' + $entries.Count + ' tweak(s)?') -Lines $lines -Notes @('The original values captured when the tweak was applied will be restored.'))) { return }
    SetCursorWait $true
    $ok = 0
    $fail = 0
    $fails = New-Object System.Collections.Generic.List[string]
    foreach ($e in $entries) {
        $r = Invoke-RevertTweakEntry -Entry $e
        if ($r.Ok) { $ok++ } else { $fail++; [void]$fails.Add([string]$r.Msg) }
    }
    SetCursorWait $false
    Refresh-TweakStatuses -Keys @($entries | ForEach-Object { [string]$_.key })
    Refresh-History
    $msg = 'Reverted: ' + $ok + '    Failed: ' + $fail
    if ($fail -gt 0) { Show-Err ($msg + [Environment]::NewLine + ($fails -join [Environment]::NewLine)) 'Revert result' }
    else { Show-Info $msg 'Revert result' }
}

function Apply-CurrentPreset {
    $preset = [string]$script:CmbPreset.SelectedItem
    if (-not $preset -or -not $Presets.ContainsKey($preset)) { Show-Info 'Pick a preset first.'; return }
    $keys = @($Presets[$preset])
    $lines = @()
    foreach ($k in $keys) {
        $t = $TweakByKey[$k]
        if ($t) { $lines += ('APPLY: ' + $t.Name) }
    }
    if (-not (Show-ConfirmDialog -Title ('Apply preset "' + $preset + '" (' + $keys.Count + ' tweaks)?') -Lines $lines -Notes @('All tweaks in the preset will be applied with the same plan preview as a normal apply.'))) { return }
    $script:TxtTweakSearch.Text = ''
    $script:CmbTweakCategory.SelectedItem = 'All'
    Build-TweakRows
    foreach ($k in $keys) {
        if ($script:TweakRows.ContainsKey($k)) { $script:TweakRows[$k].Check.IsChecked = $true }
    }
    Apply-TweaksSelected
}

$WingetListBody = @'
if (-not (Test-WinGetAvailable)) { throw 'winget is not available' }
$out = (& winget.exe list --accept-source-agreements 2>$null | Out-String)
$rows = ConvertFrom-WingetTable $out
$arr = New-Object System.Collections.Generic.List[object]
foreach ($r in $rows) {
    if ($r.Id) { $arr.Add([PSCustomObject]@{ Id = $r.Id; Name = $r.Name; Version = $r.Version }) }
}
if ($arr.Count -eq 0) { $json = '[]' } else { $json = @($arr.ToArray()) | ConvertTo-Json -Depth 5 }
[System.IO.File]::WriteAllText(($log + '.json'), $json, (New-Object System.Text.UTF8Encoding($false)))
W('Installed packages detected: ' + $arr.Count)
W('DONE')
'@

$UpgradeScanBody = @'
if (-not (Test-WinGetAvailable)) { throw 'winget is not available' }
$out = (& winget.exe upgrade --accept-source-agreements 2>$null | Out-String)
$rows = ConvertFrom-WingetTable $out
$arr = New-Object System.Collections.Generic.List[object]
foreach ($r in $rows) {
    if ($r.Id) { $arr.Add([PSCustomObject]@{ Id = $r.Id; Name = $r.Name; Version = $r.Version; Available = $r.Available }) }
}
if ($arr.Count -eq 0) { $json = '[]' } else { $json = @($arr.ToArray()) | ConvertTo-Json -Depth 5 }
[System.IO.File]::WriteAllText(($log + '.json'), $json, (New-Object System.Text.UTF8Encoding($false)))
W('Updates available: ' + $arr.Count)
W('DONE')
'@

$InstallBody = @'
if (-not (Test-WinGetAvailable)) { throw 'winget is not available' }
$apps = @($Payload['Apps'])
$results = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($a in $apps) {
    $i++
    $id = [string]$a['Id']
    $nm = [string]$a['Name']
    W('(' + $i + '/' + $apps.Count + ') Installing ' + $nm + '  [' + $id + '] ...')
    $out = (& winget.exe install --id $id --exact --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-String)
    $code = $LASTEXITCODE
    $ok = ($code -eq 0) -or ($code -eq -1978335189)
    if ($ok) { W('  OK') }
    else {
        W('  exit code: ' + $code)
        foreach ($ln in (@($out -split "`r?`n") | Where-Object { $_ -and $_.Trim() } | Select-Object -Last 3)) { W('  ' + $ln) }
    }
    $results.Add([PSCustomObject]@{ Id = $id; Name = $nm; Code = $code; Ok = $ok })
}
if ($results.Count -eq 0) { $json = '[]' } else { $json = @($results.ToArray()) | ConvertTo-Json -Depth 4 }
[System.IO.File]::WriteAllText(($log + '.json'), $json, (New-Object System.Text.UTF8Encoding($false)))
W('Install pass finished.')
W('DONE')
'@

$UpgradeBody = @'
if (-not (Test-WinGetAvailable)) { throw 'winget is not available' }
$apps = @($Payload['Apps'])
$results = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($a in $apps) {
    $i++
    $id = [string]$a['Id']
    $nm = [string]$a['Name']
    W('(' + $i + '/' + $apps.Count + ') Upgrading ' + $nm + '  [' + $id + '] ...')
    $out = (& winget.exe upgrade --id $id --exact --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-String)
    $code = $LASTEXITCODE
    $ok = ($code -eq 0) -or ($code -eq -1978335189)
    if ($ok) { W('  OK') }
    else {
        W('  exit code: ' + $code)
        foreach ($ln in (@($out -split "`r?`n") | Where-Object { $_ -and $_.Trim() } | Select-Object -Last 3)) { W('  ' + $ln) }
    }
    $results.Add([PSCustomObject]@{ Id = $id; Name = $nm; Code = $code; Ok = $ok })
}
if ($results.Count -eq 0) { $json = '[]' } else { $json = @($results.ToArray()) | ConvertTo-Json -Depth 4 }
[System.IO.File]::WriteAllText(($log + '.json'), $json, (New-Object System.Text.UTF8Encoding($false)))
W('Upgrade pass finished.')
W('DONE')
'@

function Start-WingetJob {
    param(
        [string]$Kind, [string]$Title, [string]$BodyText,
        $Payload = $null, [scriptblock]$OnDone = $null
    )
    $text = $WorkerSrc + [Environment]::NewLine + $BodyText
    $null = Start-BgOperation -Kind $Kind -Title $Title -Body ([scriptblock]::Create($text)) -Payload $Payload -OnDone $OnDone
}

function Start-WingetListRefresh {
    if (-not $script:WingetOk) { return }
    $done = {
        param($result)
        if ($result.State -eq 'Completed' -and $result.Data) {
            $h = @{}
            foreach ($it in @($result.Data)) {
                $d = ConvertTo-HashtableDeep $it
                if ($d['Id']) { $h[([string]$d['Id']).ToLower()] = $d }
            }
            $script:WgInstalled = $h
            Build-AppRows
            Write-Log ('Installed-apps cache updated: ' + $h.Count + ' packages.')
        } elseif ($result.State -ne 'Completed') {
            Write-Log ('Installed-apps refresh failed: ' + [string]$result.Error)
        }
    }
    Start-WingetJob -Kind 'wglist' -Title 'Reading installed packages (winget)...' -BodyText $WingetListBody -Payload $null -OnDone $done
}

$script:AppRows = @{}
$script:WgInstalled = @{}
$script:WingetOk = $false

function Build-AppRows {
    $script:PnlApps.Children.Clear()
    $script:AppRows = @{}
    $q = [string]$script:TxtAppSearch.Text
    $q = $q.Trim().ToLower()
    $cat = [string]$script:CmbAppCategory.SelectedItem
    $onlyInst = ($script:ChkAppsInstalledOnly.IsChecked -eq $true)
    $groups = @{}
    $order = New-Object System.Collections.Generic.List[string]
    foreach ($a in $AppCatalog) {
        if ($cat -and $cat -ne 'All' -and $a.Category -ne $cat) { continue }
        if ($q) {
            $hay = ($a.Name + ' ' + $a.Id + ' ' + $a.Category).ToLower()
            if (-not $hay.Contains($q)) { continue }
        }
        $installed = $script:WgInstalled.ContainsKey($a.Id.ToLower())
        if ($onlyInst -and (-not $installed)) { continue }
        if (-not $groups.ContainsKey($a.Category)) {
            $groups[$a.Category] = New-Object System.Collections.Generic.List[object]
            [void]$order.Add($a.Category)
        }
        [void]$groups[$a.Category].Add($a)
    }
    foreach ($c in $order) {
        [void]$script:PnlApps.Children.Add((New-GroupHeader $c))
        foreach ($a in $groups[$c]) {
            $installed = $script:WgInstalled.ContainsKey($a.Id.ToLower())
            $row = New-Object System.Windows.Controls.StackPanel
            $row.Orientation = 'Horizontal'
            $row.Margin = New-Object System.Windows.Thickness(6, 2, 6, 2)
            $cb = New-Object System.Windows.Controls.CheckBox
            $cb.MinWidth = 330
            $cb.Tag = $a.Id
            $cb.Content = $a.Name
            $idTb = New-Object System.Windows.Controls.TextBlock
            $idTb.Text = $a.Id
            $idTb.Foreground = $script:BrDim
            $idTb.MinWidth = 300
            $idTb.Margin = New-Object System.Windows.Thickness(10, 0, 10, 0)
            $st = New-Object System.Windows.Controls.TextBlock
            $st.Tag = ('apst_' + $a.Id)
            if ($installed) { $st.Text = 'installed'; $st.Foreground = $script:BrGreen }
            else { $st.Text = '' }
            [void]$row.Children.Add($cb)
            [void]$row.Children.Add($idTb)
            [void]$row.Children.Add($st)
            [void]$script:PnlApps.Children.Add($row)
            $script:AppRows[$a.Id] = @{ Check = $cb; Status = $st }
        }
    }
}

function Get-SelectedApps {
    $sel = New-Object System.Collections.Generic.List[object]
    foreach ($id in @($script:AppRows.Keys)) {
        $row = $script:AppRows[$id]
        if ($row.Check -and $row.Check.IsChecked -eq $true) {
            $name = $id
            foreach ($a in $AppCatalog) { if ($a.Id -eq $id) { $name = $a.Name; break } }
            $sel.Add(@{ Id = $id; Name = $name })
        }
    }
    return $sel.ToArray()
}

function Install-AppsSelected {
    if (-not $script:WingetOk) { Show-Err 'winget is not available on this system.'; return }
    $sel = @(Get-SelectedApps)
    if ($sel.Count -eq 0) { Show-Info 'No apps are selected.'; return }
    $lines = @()
    foreach ($s in $sel) { $lines += ('INSTALL: ' + [string]$s['Name'] + '  [' + [string]$s['Id'] + ']') }
    if (-not (Show-ConfirmDialog -Title ('Install ' + $sel.Count + ' app(s) with winget?') -Lines $lines -Notes @('Installs run silently (--silent) and accept package agreements. Some installers may still show a window or need a restart.'))) { return }
    $payload = @{ Apps = $sel }
    $done = {
        param($result)
        if ($result.State -ne 'Completed') {
            Show-Err ('The install operation did not finish (state: ' + $result.State + ').' + [Environment]::NewLine + [string]$result.Error) 'Install'
            return
        }
        $okNames = @()
        $failLines = @()
        foreach ($it in @($result.Data)) {
            $d = ConvertTo-HashtableDeep $it
            if ([bool]$d['Ok']) {
                $okNames += [string]$d['Name']
                Add-InstalledApp -WingetId ([string]$d['Id']) -DisplayName ([string]$d['Name'])
            } else {
                $failLines += ([string]$d['Name'] + '  (exit code ' + [string]$d['Code'] + ')')
            }
        }
        Refresh-History
        $msg = 'Installed: ' + $okNames.Count
        if ($failLines.Count -gt 0) {
            $msg = $msg + '    Failed: ' + $failLines.Count + [Environment]::NewLine + ($failLines -join [Environment]::NewLine)
            Show-Err $msg 'Install result'
        } else {
            Show-Info $msg 'Install result'
        }
        Start-WingetListRefresh
    }
    Start-WingetJob -Kind 'install' -Title ('Installing ' + $sel.Count + ' app(s) via winget...') -BodyText $InstallBody -Payload $payload -OnDone $done
}

function Scan-Upgrades {
    if (-not $script:WingetOk) { Show-Err 'winget is not available on this system.'; return }
    $done = {
        param($result)
        if ($result.State -eq 'Completed' -and $result.Data) {
            Build-UpgradeRows -Rows @($result.Data)
        } elseif ($result.State -eq 'Completed') {
            $script:PnlUpgrades.Children.Clear()
            $script:TxtUpgradeInfo.Text = 'No updates available.'
        } else {
            $script:TxtUpgradeInfo.Text = 'Update check failed: ' + [string]$result.Error
        }
    }
    Start-WingetJob -Kind 'upgscan' -Title 'Checking for app updates (winget)...' -BodyText $UpgradeScanBody -Payload $null -OnDone $done
}

function Build-UpgradeRows {
    param($Rows)
    $script:PnlUpgrades.Children.Clear()
    $n = 0
    foreach ($r in $Rows) {
        $d = ConvertTo-HashtableDeep $r
        if (-not $d['Id']) { continue }
        $n++
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Tag = [string]$d['Id']
        $cb.IsChecked = $true
        $cb.Margin = New-Object System.Windows.Thickness(4, 2, 4, 2)
        $ver = [string]$d['Version']
        $av = [string]$d['Available']
        if ($av) { $cb.Content = ([string]$d['Name'] + '   ' + $ver + '  ->  ' + $av) }
        else     { $cb.Content = ([string]$d['Name'] + '   ' + $ver) }
        [void]$script:PnlUpgrades.Children.Add($cb)
    }
    if ($n -eq 0) { $script:TxtUpgradeInfo.Text = 'No updates available.' }
    else { $script:TxtUpgradeInfo.Text = ($n.ToString() + ' update(s) found. Selected ones will be upgraded.') }
}

function Upgrade-AppsSelected {
    if (-not $script:WingetOk) { Show-Err 'winget is not available on this system.'; return }
    $sel = New-Object System.Collections.Generic.List[object]
    foreach ($el in $script:PnlUpgrades.Children) {
        if ($el -is [System.Windows.Controls.CheckBox] -and $el.IsChecked -eq $true) {
            $id = [string]$el.Tag
            $sel.Add(@{ Id = $id; Name = [string]$el.Content })
        }
    }
    if ($sel.Count -eq 0) { Show-Info 'No updates are selected.'; return }
    $lines = @()
    foreach ($s in $sel) { $lines += ('UPGRADE: ' + [string]$s['Name']) }
    if (-not (Show-ConfirmDialog -Title ('Upgrade ' + $sel.Count + ' app(s)?') -Lines $lines -Notes @('Upgrades run silently with winget.'))) { return }
    $payload = @{ Apps = $sel.ToArray() }
    $done = {
        param($result)
        if ($result.State -ne 'Completed') {
            Show-Err ('The upgrade operation did not finish (state: ' + $result.State + ').' + [Environment]::NewLine + [string]$result.Error) 'Upgrade'
            return
        }
        $ok = 0
        $failLines = @()
        foreach ($it in @($result.Data)) {
            $d = ConvertTo-HashtableDeep $it
            if ([bool]$d['Ok']) { $ok++ } else { $failLines += ([string]$d['Name'] + '  (exit code ' + [string]$d['Code'] + ')') }
        }
        $msg = 'Upgraded: ' + $ok
        if ($failLines.Count -gt 0) {
            $msg = $msg + '    Failed: ' + $failLines.Count + [Environment]::NewLine + ($failLines -join [Environment]::NewLine)
            Show-Err $msg 'Upgrade result'
        } else {
            Show-Info $msg 'Upgrade result'
        }
        $script:PnlUpgrades.Children.Clear()
        Start-WingetListRefresh
    }
    Start-WingetJob -Kind 'upgrade' -Title ('Upgrading ' + $sel.Count + ' app(s) via winget...') -BodyText $UpgradeBody -Payload $payload -OnDone $done
}


$script:PosEntries = @()
$script:PosView = @()

function Load-InstalledPrograms {
    SetCursorWait $true
    try {
        $script:PosEntries = @(Get-UninstallEntries | Sort-Object DisplayName)
    } catch {
        Write-Log ('Could not read installed programs: ' + $_.Exception.Message)
        $script:PosEntries = @()
    } finally { SetCursorWait $false }
    Update-UninstallList
    Write-Log ('Installed programs loaded: ' + $script:PosEntries.Count)
}

function Update-UninstallList {
    $script:LstUninstallPrograms.Items.Clear()
    $f = [string]$script:TxtUninstallFilter.Text
    $f = $f.Trim().ToLower()
    $view = New-Object System.Collections.Generic.List[object]
    foreach ($e in $script:PosEntries) {
        if ($f) {
            $hay = ([string]$e.DisplayName + ' ' + [string]$e.Publisher).ToLower()
            if (-not $hay.Contains($f)) { continue }
        }
        $view.Add($e)
        $line = [string]$e.DisplayName
        if ($e.Publisher) { $line = $line + '  -  ' + [string]$e.Publisher }
        if ($e.Version) { $line = $line + '  v' + [string]$e.Version }
        [void]$script:LstUninstallPrograms.Items.Add($line)
    }
    $script:PosView = $view.ToArray()
    $script:TxtUninstallInfo.Text = ($script:PosView.Count.ToString() + ' program(s) listed.')
}

function Start-DeepScan {
    param([bool]$Manual)
    if ($script:BgJob) { Show-Info 'Another operation is still running. Wait for it to finish.'; return }
    $entry = $null
    $nm = ''
    if ($Manual) {
        $nm = [string]$script:TxtManualAppName.Text
        $nm = $nm.Trim()
        if (-not $nm) { Show-Info 'Type the app name in the box first.'; return }
    } else {
        $idx = $script:LstUninstallPrograms.SelectedIndex
        if ($idx -lt 0 -or $idx -ge $script:PosView.Count) { Show-Info 'Pick a program from the list first.'; return }
        $entry = $script:PosView[$idx]
        $nm = [string]$entry.DisplayName
    }
    $pub = ''
    $loc = ''
    $cmd = ''
    if ($entry) {
        $pub = [string]$entry.Publisher
        $loc = [string]$entry.InstallLocation
        if ([string]$entry.QuietUninstallString) { $cmd = [string]$entry.QuietUninstallString }
        else { $cmd = [string]$entry.UninstallString }
    }
    $ranUninstaller = $false
    if ($script:ChkRunUninstaller.IsChecked -eq $true) {
        if ($cmd) { $ranUninstaller = $true }
        else { Write-Log 'No uninstall command available for this entry - the scan will only look for leftovers.' }
    }
    $appName = $nm
    $payload = @{
        DisplayName      = $nm
        Publisher        = $pub
        InstallLocation  = $loc
        UninstallCommand = $cmd
        RunUninstaller   = $ranUninstaller
    }
    $done = {
        param($result)
        if ($result.State -ne 'Completed') {
            Show-Err ('The deep scan did not finish (' + $result.State + ').' + [Environment]::NewLine + [string]$result.Error) 'Deep uninstall'
            return
        }
        $d = ConvertTo-HashtableDeep $result.Data
        $shownName = $appName
        if ($d -and $d['App']) { $shownName = [string]$d['App'] }
        $items = New-Object System.Collections.Generic.List[object]
        if ($d -and $d['Items']) {
            foreach ($it in @($d['Items'])) { if ($it) { $items.Add($it) } }
        }
        if ($items.Count -eq 0) {
            Show-Info ('No leftovers were found for: ' + $shownName) 'Deep uninstall'
            return
        }
        $rev = Show-LeftoverReviewDialog -AppName $shownName -Items $items.ToArray()
        if ($rev) {
            Write-Log ('Deep uninstall [' + $shownName + ']: mode ' + [string]$rev['Mode'] + ', removed ' + [string]$rev['Ok'] + ', failed ' + [string]$rev['Fail'])
            if ([int]$rev['Fail'] -gt 0) {
                Show-Err ('Some items could not be removed:' + [Environment]::NewLine + (@($rev['Failures']) -join [Environment]::NewLine)) 'Deep uninstall'
            } else {
                Show-Info ('Done. Removed items: ' + [string]$rev['Ok'] + '   (mode: ' + [string]$rev['Mode'] + ')') 'Deep uninstall'
            }
            Refresh-QuarantineView
        }
        if ($ranUninstaller) { Load-InstalledPrograms }
    }.GetNewClosure()
    Start-WingetJob -Kind 'scan' -Title ('Deep scan: ' + $nm) -BodyText $UninstallScanBody -Payload $payload -OnDone $done
}

function Format-SizeBytes {
    param([long]$Bytes)
    if ($Bytes -ge 1073741824) { return ('{0:N2} GB' -f ($Bytes / 1073741824.0)) }
    if ($Bytes -ge 1048576)    { return ('{0:N1} MB' -f ($Bytes / 1048576.0)) }
    if ($Bytes -ge 1024)       { return ('{0:N0} KB' -f ($Bytes / 1024.0)) }
    return ($Bytes.ToString() + ' B')
}

function Get-PathSizeBytes {
    param([string]$Path)
    $sum = [long]0
    if (-not $Path) { return $sum }
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $sum }
        foreach ($f in @(Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue)) {
            try { $sum += [long]$f.Length } catch { }
        }
    } catch { }
    return $sum
}

$script:CleanupTargets = @(
    @{ Title = 'User temp';          Kind = 'Dir';     Paths = @($env:TEMP);                                                             Patterns = @();                              Chk = $script:ChkClnUserTemp;     Txt = $script:TxtClnUserTemp }
    @{ Title = 'Windows temp';       Kind = 'Dir';     Paths = @((Join-Path $env:windir 'Temp'));                                        Patterns = @();                              Chk = $script:ChkClnWindowsTemp;  Txt = $script:TxtClnWindowsTemp }
    @{ Title = 'Windows Update cache'; Kind = 'Dir';   Paths = @((Join-Path $env:windir 'SoftwareDistribution\Download'));               Patterns = @();                              Chk = $script:ChkClnUpdateCache;  Txt = $script:TxtClnUpdateCache }
    @{ Title = 'Delivery Optimization'; Kind = 'Dir';  Paths = @((Join-Path $env:windir 'SoftwareDistribution\DeliveryOptimization'), (Join-Path $env:windir 'ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization')); Patterns = @(); Chk = $script:ChkClnDeliveryOpt; Txt = $script:TxtClnDeliveryOpt }
    @{ Title = 'Error reporting archives'; Kind = 'Dir'; Paths = @((Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive'), (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportQueue')); Patterns = @(); Chk = $script:ChkClnWerReports; Txt = $script:TxtClnWerReports }
    @{ Title = 'Thumbnail and icon cache'; Kind = 'Files'; Paths = @((Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Explorer'));         Patterns = @('thumbcache_*.db','iconcache_*.db'); Chk = $script:ChkClnThumbCache; Txt = $script:TxtClnThumbCache }
    @{ Title = 'Internet cache';     Kind = 'Dir';     Paths = @((Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\INetCache'));             Patterns = @();                              Chk = $script:ChkClnINetCache;    Txt = $script:TxtClnINetCache }
    @{ Title = 'Direct3D shader cache'; Kind = 'Dir';  Paths = @((Join-Path $env:LOCALAPPDATA 'D3DSCache'));                             Patterns = @();                              Chk = $script:ChkClnD3DSCache;    Txt = $script:TxtClnD3DSCache }
    @{ Title = 'Recycle Bin';        Kind = 'Recycle'; Paths = @();                                                                    Patterns = @();                              Chk = $script:ChkClnRecycleBin;   Txt = $script:TxtClnRecycleBin }
)

$CleanupBody = @'
function Get-JobPathSize {
    param([string]$Path)
    $sum = [long]0
    if (-not $Path) { return $sum }
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $sum }
        foreach ($f in @(Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue)) {
            try { $sum += [long]$f.Length } catch { }
        }
    } catch { }
    return $sum
}
function Format-JobSize {
    param([long]$Bytes)
    if ($Bytes -ge 1073741824) { return ('{0:N2} GB' -f ($Bytes / 1073741824.0)) }
    if ($Bytes -ge 1048576)    { return ('{0:N1} MB' -f ($Bytes / 1048576.0)) }
    if ($Bytes -ge 1024)       { return ('{0:N0} KB' -f ($Bytes / 1024.0)) }
    return ($Bytes.ToString() + ' B')
}
$targets = @($Payload['Targets'])
$results = New-Object System.Collections.Generic.List[object]
foreach ($t in $targets) {
    $name = [string]$t['Title']
    $kind = [string]$t['Kind']
    $paths = @($t['Paths'])
    $patterns = @($t['Patterns'])
    W('Cleaning: ' + $name)
    $before = [long]0
    if ($kind -ne 'Recycle') {
        foreach ($p in $paths) { $before += (Get-JobPathSize -Path $p) }
        W('  size before: ' + (Format-JobSize -Bytes $before))
    }
    if ($kind -eq 'Recycle') {
        try {
            Clear-RecycleBin -Force -ErrorAction Stop
            W('  Recycle Bin emptied.')
        } catch {
            W('  Recycle Bin note: ' + $_.Exception.Message)
        }
    } elseif ($kind -eq 'Dir') {
        foreach ($p in $paths) {
            if (-not (Test-Path -LiteralPath $p)) { continue }
            foreach ($k in @(Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue)) {
                try { Remove-Item -LiteralPath $k.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch { }
            }
        }
    } elseif ($kind -eq 'Files') {
        foreach ($p in $paths) {
            if (-not (Test-Path -LiteralPath $p)) { continue }
            foreach ($k in @(Get-ChildItem -LiteralPath $p -Force -File -ErrorAction SilentlyContinue)) {
                $hit = $false
                foreach ($pat in $patterns) { if ($k.Name -like $pat) { $hit = $true; break } }
                if ($hit) {
                    try { Remove-Item -LiteralPath $k.FullName -Force -ErrorAction SilentlyContinue } catch { }
                }
            }
        }
    }
    $after = [long]0
    if ($kind -ne 'Recycle') {
        foreach ($p in $paths) { $after += (Get-JobPathSize -Path $p) }
    }
    $freed = $before - $after
    if ($freed -lt 0) { $freed = [long]0 }
    if ($kind -eq 'Recycle') { W('  done.') } else { W('  freed approximately: ' + (Format-JobSize -Bytes $freed)) }
    $results.Add([PSCustomObject]@{ Title = $name; Freed = $freed })
}
if ($results.Count -eq 0) { $json = '[]' } else { $json = @($results.ToArray()) | ConvertTo-Json -Depth 4 }
[System.IO.File]::WriteAllText(($log + '.json'), $json, (New-Object System.Text.UTF8Encoding($false)))
W('Cleanup finished.')
W('DONE')
'@

function Invoke-CleanupAnalyze {
    SetCursorWait $true
    $total = [long]0
    try {
        foreach ($t in $script:CleanupTargets) {
            if ($t.Kind -eq 'Recycle') {
                $t.Txt.Text = '(all drives)'
                continue
            }
            $size = [long]0
            foreach ($p in $t.Paths) { $size += (Get-PathSizeBytes -Path $p) }
            $t.Txt.Text = Format-SizeBytes $size
            $total += $size
        }
    } finally { SetCursorWait $false }
    $script:TxtCleanupInfo.Text = ('Total size in listed locations: ' + (Format-SizeBytes $total))
}

function Start-CleanupRunning {
    if ($script:BgJob) { Show-Info 'Another operation is still running. Wait for it to finish.'; return }
    $sel = New-Object System.Collections.Generic.List[object]
    foreach ($t in $script:CleanupTargets) {
        if ($t.Chk.IsChecked -eq $true) {
            if ($t.Kind -eq 'Recycle') {
                $sel.Add(@{ Title = $t.Title; Kind = $t.Kind; Paths = @(); Patterns = @() })
            } else {
                $sel.Add(@{ Title = $t.Title; Kind = $t.Kind; Paths = @($t.Paths); Patterns = @($t.Patterns) })
            }
        }
    }
    if ($sel.Count -eq 0) { Show-Info 'Select at least one item to clean.'; return }
    $lines = @()
    foreach ($t in $sel.ToArray()) { $lines += ('CLEAN: ' + [string]$t['Title']) }
    if (-not (Show-ConfirmDialog -Title ('Clean ' + $sel.Count + ' location(s)?') -Lines $lines -Notes @('Files that are currently in use are skipped automatically. The Recycle Bin option empties all drives.'))) { return }
    $done = {
        param($result)
        if ($result.State -ne 'Completed') {
            Show-Err ('The cleanup did not finish (' + $result.State + ').' + [Environment]::NewLine + [string]$result.Error) 'Cleanup'
            return
        }
        $freed = [long]0
        $linesOut = @()
        foreach ($it in @($result.Data)) {
            $d = ConvertTo-HashtableDeep $it
            if (-not $d) { continue }
            $f = [long]0
            if ($d['Freed']) { $f = [long]$d['Freed'] }
            $freed += $f
            $nm = ''
            if ($d['Title']) { $nm = [string]$d['Title'] }
            if ($f -gt 0) { $linesOut += ($nm + ':  ~' + (Format-SizeBytes $f)) }
            else { $linesOut += ($nm + ':  done') }
        }
        $msg = 'Cleanup finished.  Freed approximately: ' + (Format-SizeBytes $freed)
        if ($linesOut.Count -gt 0) { $msg = $msg + [Environment]::NewLine + [Environment]::NewLine + ($linesOut -join [Environment]::NewLine) }
        Show-Info $msg 'Cleanup'
        Invoke-CleanupAnalyze
    }
    Start-WingetJob -Kind 'cleanup' -Title ('Cleaning ' + $sel.Count + ' location(s)...') -BodyText $CleanupBody -Payload @{ Targets = $sel.ToArray() } -OnDone $done
}

$script:AppxRaw = @()

function Load-AppxPackages {
    SetCursorWait $true
    try {
        $script:AppxRaw = @(Get-AppxPackage | Sort-Object Name)
    } catch {
        $script:AppxRaw = @()
        Write-Log ('AppX load failed: ' + $_.Exception.Message)
    } finally { SetCursorWait $false }
    $script:LstAppx.Items.Clear()
    foreach ($p in $script:AppxRaw) {
        [void]$script:LstAppx.Items.Add(([string]$p.Name + '   ' + [string]$p.Version))
    }
    $script:TxtAppxInfo.Text = ($script:AppxRaw.Count.ToString() + ' AppX package(s) found.')
    Write-Log ('AppX packages loaded: ' + $script:AppxRaw.Count)
}

$AppxBody = @'
$pkgs = @($Payload['Packages'])
$prov = [bool]$Payload['Provisioned']
$provList = @()
if ($prov) {
    try { $provList = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop) }
    catch { W('Could not enumerate provisioned packages: ' + $_.Exception.Message) }
}
$results = New-Object System.Collections.Generic.List[object]
foreach ($p in $pkgs) {
    $dn = [string]$p['Name']
    $fn = [string]$p['FullName']
    W('Removing: ' + $dn)
    $ok = $false
    try {
        Remove-AppxPackage -Package $fn -ErrorAction Stop
        W('  removed for the current user.')
        $ok = $true
    } catch {
        W('  FAILED: ' + $_.Exception.Message)
    }
    if ($prov) {
        foreach ($pp in $provList) {
            if ($pp.DisplayName -eq $dn) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction Stop | Out-Null
                    W('  provisioned copy removed: ' + $pp.PackageName)
                } catch {
                    W('  provisioned removal failed: ' + $_.Exception.Message)
                }
            }
        }
    }
    $results.Add([PSCustomObject]@{ Name = $dn; Ok = $ok })
}
if ($results.Count -eq 0) { $json = '[]' } else { $json = @($results.ToArray()) | ConvertTo-Json -Depth 4 }
[System.IO.File]::WriteAllText(($log + '.json'), $json, (New-Object System.Text.UTF8Encoding($false)))
W('AppX removal pass finished.')
W('DONE')
'@

function Remove-SelectedAppx {
    if ($script:BgJob) { Show-Info 'Another operation is still running. Wait for it to finish.'; return }
    $sel = @($script:LstAppx.SelectedItems)
    if ($sel.Count -eq 0) { Show-Info 'Select one or more packages in the list first.'; return }
    $pkgs = New-Object System.Collections.Generic.List[object]
    foreach ($s in $sel) {
        $idx = $script:LstAppx.Items.IndexOf($s)
        if ($idx -ge 0 -and $idx -lt $script:AppxRaw.Count) {
            $p = $script:AppxRaw[$idx]
            $pkgs.Add(@{ Name = [string]$p.Name; FullName = [string]$p.PackageFullName; FamilyName = [string]$p.PackageFamilyName })
        }
    }
    if ($pkgs.Count -eq 0) { Show-Info 'Could not map the selection to packages.'; return }
    $prov = ($script:ChkAppxAllUsers.IsChecked -eq $true)
    $lines = @()
    foreach ($p in $pkgs.ToArray()) { $lines += ('REMOVE: ' + [string]$p['Name']) }
    $note = 'The package is removed for the current user.'
    if ($prov) { $note = $note + ' The provisioned copy is also removed so Windows does not reinstall it for new users.' }
    if (-not (Show-ConfirmDialog -Title ('Remove ' + $pkgs.Count + ' AppX package(s)?') -Lines $lines -Notes @($note))) { return }
    $done = {
        param($result)
        if ($result.State -ne 'Completed') {
            Show-Err ('AppX removal did not finish (' + $result.State + ').' + [Environment]::NewLine + [string]$result.Error) 'Bloatware'
            Load-AppxPackages
            return
        }
        $ok = 0
        $fails = @()
        foreach ($it in @($result.Data)) {
            $d = ConvertTo-HashtableDeep $it
            if ($d -and [bool]$d['Ok']) { $ok++ }
            else {
                $nm = '(unknown)'
                if ($d -and $d['Name']) { $nm = [string]$d['Name'] }
                $fails += ($nm + ' could not be removed')
            }
        }
        if ($fails.Count -gt 0) {
            Show-Err ('Removed: ' + $ok + [Environment]::NewLine + [Environment]::NewLine + 'Problems:' + [Environment]::NewLine + ($fails -join [Environment]::NewLine)) 'Bloatware'
        } else {
            Show-Info ('Removed packages: ' + $ok) 'Bloatware'
        }
        Load-AppxPackages
    }
    Start-WingetJob -Kind 'appx' -Title ('Removing ' + $pkgs.Count + ' AppX package(s)...') -BodyText $AppxBody -Payload @{ Packages = $pkgs.ToArray(); Provisioned = $prov } -OnDone $done
}

function Get-PropSafe {
    param($Obj, [string]$Name)
    try {
        $p = $Obj.PSObject.Properties[$Name]
        if ($p) { return $p.Value }
    } catch { }
    return $null
}

function Refresh-SecurityReport {
    SetCursorWait $true
    try {
        $lines = New-Object System.Collections.Generic.List[string]
        $summary = ''
        [void]$lines.Add('Report generated: ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
        [void]$lines.Add('')
        [void]$lines.Add('--- Microsoft Defender ---')
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $av = Get-PropSafe $mp 'AntivirusEnabled'
            $rt = Get-PropSafe $mp 'RealTimeProtectionEnabled'
            $bm = Get-PropSafe $mp 'BehaviorMonitorEnabled'
            $nis = Get-PropSafe $mp 'NISEnabled'
            $tamper = Get-PropSafe $mp 'IsTamperProtected'
            $amsvc = Get-PropSafe $mp 'AMServiceEnabled'
            $eng = Get-PropSafe $mp 'AMEngineVersion'
            $sigv = Get-PropSafe $mp 'AntivirusSignatureVersion'
            $sigdate = Get-PropSafe $mp 'AntivirusSignatureLastUpdated'
            [void]$lines.Add('Antivirus enabled:        ' + [string]$av)
            [void]$lines.Add('Real-time protection:     ' + [string]$rt)
            [void]$lines.Add('Behavior monitoring:      ' + [string]$bm)
            [void]$lines.Add('Network inspection (NIS): ' + [string]$nis)
            [void]$lines.Add('Tamper protection:        ' + [string]$tamper)
            [void]$lines.Add('AM service running:       ' + [string]$amsvc)
            [void]$lines.Add('Engine version:           ' + [string]$eng)
            [void]$lines.Add('Signature version:        ' + [string]$sigv)
            $ageDays = -1
            if ($sigdate) {
                try { $ageDays = [int][math]::Floor(((Get-Date) - [datetime]$sigdate).TotalDays) } catch { $ageDays = -1 }
            }
            if ($ageDays -ge 0) {
                [void]$lines.Add('Signature age:            ' + $ageDays + ' day(s)')
                if ($ageDays -gt 3) { [void]$lines.Add('WARNING: signatures look old. Use the Update signatures button.') }
            }
            $summary = 'Defender: ON, real-time: ' + [string]$rt
            if ($ageDays -ge 0) { $summary = $summary + ', signatures ' + $ageDays + 'd old' }
        } catch {
            [void]$lines.Add('Defender status unavailable: ' + $_.Exception.Message)
            $summary = 'Defender status unavailable'
        }
        [void]$lines.Add('')
        [void]$lines.Add('--- Firewall ---')
        try {
            foreach ($p in @(Get-NetFirewallProfile -ErrorAction Stop)) {
                [void]$lines.Add('Profile ' + [string]$p.Name + ': enabled = ' + [string]$p.Enabled)
            }
        } catch {
            [void]$lines.Add('Firewall status unavailable: ' + $_.Exception.Message)
        }
        [void]$lines.Add('')
        [void]$lines.Add('--- System protections ---')
        try {
            $lua = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction Stop
            $uacOn = ([int](Get-PropSafe $lua 'EnableLUA') -eq 1)
            [void]$lines.Add('UAC enabled:              ' + [string]$uacOn)
        } catch {
            [void]$lines.Add('UAC status unavailable.')
        }
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            [void]$lines.Add('Secure Boot enabled:      ' + [string]$sb)
        } catch {
            [void]$lines.Add('Secure Boot: not available (legacy BIOS or not supported).')
        }
        try {
            $threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
            [void]$lines.Add('Recent threat detections: ' + $threats.Count)
        } catch { }
        $script:TxtSecReport.Text = ($lines -join [Environment]::NewLine)
        $script:TxtSecInfo.Text = $summary
    } finally { SetCursorWait $false }
}

$DefenderBody = @'
$action = [string]$Payload['Action']
W('Defender action: ' + $action)
if ($action -eq 'update') {
    Update-MpSignature -ErrorAction Stop
    W('Signatures updated.')
} elseif ($action -eq 'quick') {
    W('Quick scan starting... this can take several minutes.')
    Start-MpScan -ScanType QuickScan -ErrorAction Stop
    W('Quick scan finished.')
} elseif ($action -eq 'full') {
    W('Full scan starting... this can take a long time (up to a few hours).')
    Start-MpScan -ScanType FullScan -ErrorAction Stop
    W('Full scan finished.')
} else {
    throw ('unknown defender action: ' + $action)
}
$threats = @()
try { $threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue) } catch { }
$obj = [PSCustomObject]@{ Action = $action; Threats = $threats.Count }
[System.IO.File]::WriteAllText(($log + '.json'), ($obj | ConvertTo-Json -Depth 3), (New-Object System.Text.UTF8Encoding($false)))
W('Recent threat detections: ' + $threats.Count)
W('DONE')
'@

function Start-DefenderAction {
    param([string]$Action, [string]$Title, [string]$ConfirmText)
    if ($script:BgJob) { Show-Info 'Another operation is still running. Wait for it to finish.'; return }
    if ($ConfirmText) {
        if (-not (Ask-YesNo $ConfirmText 'Windows Security')) { return }
    }
    $done = {
        param($result)
        if ($result.State -eq 'Completed') {
            Show-Info 'The Defender action finished.' 'Windows Security'
        } else {
            Show-Err ('The Defender action did not finish (' + $result.State + ').' + [Environment]::NewLine + [string]$result.Error) 'Windows Security'
        }
        Refresh-SecurityReport
    }
    Start-WingetJob -Kind 'defender' -Title $Title -BodyText $DefenderBody -Payload @{ Action = $Action } -OnDone $done
}


$script:ClosingOk = $false

$WingetUninstallBody = @'
if (-not (Test-WinGetAvailable)) { throw 'winget is not available' }
$id = [string]$Payload['Id']
$nm = [string]$Payload['Name']
W('Uninstalling: ' + $nm + '  [' + $id + ']')
$out = (& winget.exe uninstall --id $id --exact --silent --accept-source-agreements 2>&1 | Out-String)
$code = $LASTEXITCODE
$ok = ($code -eq 0) -or ($code -eq -1978335189)
if ($ok) { W('  OK') }
else {
    W('  exit code: ' + $code)
    foreach ($ln in (@($out -split "`r?`n") | Where-Object { $_ -and $_.Trim() } | Select-Object -Last 3)) { W('  ' + $ln) }
}
$obj = [PSCustomObject]@{ Id = $id; Name = $nm; Ok = $ok; Code = $code }
[System.IO.File]::WriteAllText(($log + '.json'), ($obj | ConvertTo-Json -Depth 3), (New-Object System.Text.UTF8Encoding($false)))
W('DONE')
'@

function Refresh-History {
    $log = Get-ActionLog
    $script:PnlHistoryTweaks.Children.Clear()
    $tw = @($log.appliedTweaks)
    if ($tw.Count -eq 0) {
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = 'No tweaks are currently applied by STweak.'
        $tb.Foreground = $script:BrDim
        $tb.Margin = New-Object System.Windows.Thickness(6, 2, 6, 2)
        [void]$script:PnlHistoryTweaks.Children.Add($tb)
    } else {
        foreach ($e in $tw) {
            $row = New-Object System.Windows.Controls.StackPanel
            $row.Orientation = 'Horizontal'
            $row.Margin = New-Object System.Windows.Thickness(6, 2, 6, 2)
            $dateText = ''
            try { if ($e.date) { $dateText = ([datetime]$e.date).ToString('yyyy-MM-dd HH:mm') } } catch { $dateText = '' }
            $tb = New-Object System.Windows.Controls.TextBlock
            $tb.Text = ([string]$e.name + '   (' + $dateText + ')')
            $tb.MinWidth = 540
            $tb.VerticalAlignment = 'Center'
            [void]$row.Children.Add($tb)
            $btn = New-Object System.Windows.Controls.Button
            $btn.Content = 'Revert'
            $btn.Tag = $e
            $btn.Add_Click({
                param($sender, $args)
                $entry = $sender.Tag
                $nm = [string]$entry.name
                if (-not (Ask-YesNo ('Revert this tweak now?' + [Environment]::NewLine + [Environment]::NewLine + $nm) 'Revert tweak')) { return }
                SetCursorWait $true
                $r = Invoke-RevertTweakEntry -Entry $entry
                SetCursorWait $false
                if (-not $r.Ok) { Show-Err ([string]$r.Msg) 'Revert' }
                Refresh-History
                Refresh-TweakStatuses
            })
            [void]$row.Children.Add($btn)
            [void]$script:PnlHistoryTweaks.Children.Add($row)
        }
    }
    $script:PnlHistoryApps.Children.Clear()
    $ap = @($log.installedApps)
    if ($ap.Count -eq 0) {
        $tb2 = New-Object System.Windows.Controls.TextBlock
        $tb2.Text = 'No apps installed by STweak yet.'
        $tb2.Foreground = $script:BrDim
        $tb2.Margin = New-Object System.Windows.Thickness(6, 2, 6, 2)
        [void]$script:PnlHistoryApps.Children.Add($tb2)
    } else {
        foreach ($e in $ap) {
            $row = New-Object System.Windows.Controls.StackPanel
            $row.Orientation = 'Horizontal'
            $row.Margin = New-Object System.Windows.Thickness(6, 2, 6, 2)
            $dateText = ''
            try { if ($e.date) { $dateText = ([datetime]$e.date).ToString('yyyy-MM-dd HH:mm') } } catch { $dateText = '' }
            $tb = New-Object System.Windows.Controls.TextBlock
            $tb.Text = ([string]$e.name + '   [' + [string]$e.id + ']   (' + $dateText + ')')
            $tb.MinWidth = 540
            $tb.VerticalAlignment = 'Center'
            [void]$row.Children.Add($tb)
            $btn = New-Object System.Windows.Controls.Button
            $btn.Content = 'Uninstall app'
            $btn.Tag = @{ Id = [string]$e.id; Name = [string]$e.name }
            $btn.Add_Click({
                param($sender, $args)
                if ($script:BgJob) { Show-Info 'Another operation is still running. Wait for it to finish.'; return }
                if (-not $script:WingetOk) { Show-Err 'winget is not available on this system.'; return }
                $info = $sender.Tag
                $idVal = [string]$info['Id']
                $nmVal = [string]$info['Name']
                if (-not (Ask-YesNo ('Uninstall this app with winget?' + [Environment]::NewLine + [Environment]::NewLine + $nmVal + [Environment]::NewLine + $idVal) 'Uninstall app')) { return }
                $done = {
                    param($result)
                    if ($result.State -ne 'Completed') {
                        Show-Err ('The uninstall did not finish (' + $result.State + ').' + [Environment]::NewLine + [string]$result.Error) 'Uninstall'
                        return
                    }
                    $d = ConvertTo-HashtableDeep $result.Data
                    if ($d -and [bool]$d['Ok']) {
                        Remove-InstalledAppEntry -WingetId $idVal
                        Show-Info ('Uninstalled: ' + $nmVal) 'Uninstall'
                    } else {
                        $codeText = 'unknown'
                        if ($d -and $d['Code']) { $codeText = [string]$d['Code'] }
                        Show-Err ('Could not uninstall ' + $nmVal + '   (exit code ' + $codeText + ').') 'Uninstall'
                    }
                    Refresh-History
                    Start-WingetListRefresh
                }.GetNewClosure()
                Start-WingetJob -Kind 'uninst' -Title ('Uninstalling ' + $nmVal + '...') -BodyText $WingetUninstallBody -Payload @{ Id = $idVal; Name = $nmVal } -OnDone $done
            })
            [void]$row.Children.Add($btn)
            [void]$script:PnlHistoryApps.Children.Add($row)
        }
    }
    $script:TxtHistoryInfo.Text = ('Tweaks applied: ' + $tw.Count + '   Apps tracked: ' + $ap.Count)
}

function Undo-AllAppliedTweaks {
    $log = Get-ActionLog
    $entries = @($log.appliedTweaks)
    if ($entries.Count -eq 0) { Show-Info 'No tweaks are currently tracked as applied.'; return }
    $lines = @()
    foreach ($e in $entries) { $lines += ('REVERT: ' + [string]$e.name) }
    if (-not (Show-ConfirmDialog -Title ('Revert all ' + $entries.Count + ' applied tweak(s)?') -Lines $lines -Notes @('The original values captured at apply time will be restored.'))) { return }
    SetCursorWait $true
    $ok = 0
    $fail = 0
    $fails = New-Object System.Collections.Generic.List[string]
    foreach ($e in $entries) {
        $r = Invoke-RevertTweakEntry -Entry $e
        if ($r.Ok) { $ok++ } else { $fail++; [void]$fails.Add([string]$r.Msg) }
    }
    SetCursorWait $false
    Refresh-History
    Refresh-TweakStatuses
    if ($fail -gt 0) {
        Show-Err ('Reverted: ' + $ok + [Environment]::NewLine + 'Failed: ' + $fail + [Environment]::NewLine + ($fails.ToArray() -join [Environment]::NewLine)) 'Undo all'
    } else {
        Show-Info ('Reverted: ' + $ok) 'Undo all'
    }
}

function Refresh-QuarantineView {
    $script:PnlQuarantine.Children.Clear()
    $entries = @(Get-QuarantineEntriesView)
    if ($entries.Count -eq 0) {
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = 'Quarantine is empty. Items removed with the Deep Uninstall tool appear here.'
        $tb.Foreground = $script:BrDim
        $tb.Margin = New-Object System.Windows.Thickness(6, 2, 6, 2)
        [void]$script:PnlQuarantine.Children.Add($tb)
    }
    foreach ($e in $entries) {
        $row = New-Object System.Windows.Controls.StackPanel
        $row.Orientation = 'Horizontal'
        $row.Margin = New-Object System.Windows.Thickness(4, 3, 4, 3)
        $left = New-Object System.Windows.Controls.StackPanel
        $left.Orientation = 'Vertical'
        $left.MinWidth = 620
        $t1 = New-Object System.Windows.Controls.TextBlock
        $t1.Text = ('[' + [string]$e.Type + ']   ' + [string]$e.OriginalPath)
        $t1.MaxWidth = 700
        [void]$left.Children.Add($t1)
        $stat = ''
        if ($e.Restored -eq $true) { $stat = '   [already restored/removed]' }
        elseif ($e.PayloadExists -eq $true) { $stat = '   [in quarantine]' }
        else { $stat = '   [payload missing]' }
        $t2 = New-Object System.Windows.Controls.TextBlock
        $t2.Text = ([string]$e.App + '   ' + [string]$e.Created + $stat)
        $t2.Foreground = $script:BrDim
        $t2.FontStyle = 'Italic'
        [void]$left.Children.Add($t2)
        [void]$row.Children.Add($left)

        $btnR = New-Object System.Windows.Controls.Button
        $btnR.Content = 'Restore'
        $btnR.Tag = $e
        $btnR.IsEnabled = (($e.PayloadExists -eq $true) -and ($e.Restored -ne $true))
        $btnR.Add_Click({
            param($sender, $args)
            $entry = $sender.Tag
            if (-not (Ask-YesNo ('Restore this item to its original location?' + [Environment]::NewLine + [Environment]::NewLine + [string]$entry.OriginalPath) 'Quarantine')) { return }
            SetCursorWait $true
            $r = Restore-QuarantineEntry -Entry $entry
            SetCursorWait $false
            if ($r.Success) { Show-Info ('Restored: ' + [string]$entry.OriginalPath) 'Quarantine' }
            else { Show-Err ([string]$r.Message) 'Quarantine' }
            Refresh-QuarantineView
        })
        [void]$row.Children.Add($btnR)

        $btnD = New-Object System.Windows.Controls.Button
        $btnD.Content = 'Delete payload'
        $btnD.Tag = $e
        $btnD.IsEnabled = ($e.PayloadExists -eq $true)
        $btnD.Add_Click({
            param($sender, $args)
            $entry = $sender.Tag
            if (-not (Ask-YesNo ('Delete this quarantined copy permanently? This cannot be undone.' + [Environment]::NewLine + [Environment]::NewLine + [string]$entry.OriginalPath) 'Quarantine')) { return }
            SetCursorWait $true
            $r = Remove-QuarantineEntry -Entry $entry
            SetCursorWait $false
            if (-not $r.Success) { Show-Err ([string]$r.Message) 'Quarantine' }
            Refresh-QuarantineView
        })
        [void]$row.Children.Add($btnD)
        [void]$script:PnlQuarantine.Children.Add($row)
    }
    $script:TxtQuarantineInfo.Text = ($entries.Count.ToString() + ' item(s)   -   folder: ' + $QuarantineDir)
}

$script:PageMap = @{
    Home       = 'PageHome'
    Apps       = 'PageApps'
    Tweaks     = 'PageTweaks'
    Uninstall  = 'PageUninstall'
    Cleanup    = 'PageCleanup'
    Bloatware  = 'PageBloatware'
    Security   = 'PageSecurity'
    History    = 'PageHistory'
    Quarantine = 'PageQuarantine'
    Log        = 'PageLog'
}
$script:NavMap = @{
    Home       = 'NavHome'
    Apps       = 'NavApps'
    Tweaks     = 'NavTweaks'
    Uninstall  = 'NavUninstall'
    Cleanup    = 'NavCleanup'
    Bloatware  = 'NavBloatware'
    Security   = 'NavSecurity'
    History    = 'NavHistory'
    Quarantine = 'NavQuarantine'
    Log        = 'NavLog'
}
$script:ActiveNavBrush = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF1B2A47'))
$script:TransparentBrush = [System.Windows.Media.Brushes]::Transparent
$script:CurrentPage = ''
$script:UiPumping = $false
$script:StatusKeys = @()
$script:StatusIndex = 0

function Set-ActiveNav {
    param([string]$Key)
    foreach ($k in @($script:NavMap.Keys)) {
        $btn = $script:Window.FindName($script:NavMap[$k])
        if ($btn) {
            if ($k -eq $Key) { $btn.Background = $script:ActiveNavBrush }
            else { $btn.Background = $script:TransparentBrush }
        }
    }
}

function Show-Page {
    param([string]$Key)
    if (-not $script:PageMap.ContainsKey($Key)) { return }
    foreach ($k in @($script:PageMap.Keys)) {
        $page = $script:Window.FindName($script:PageMap[$k])
        if ($page) {
            if ($k -eq $Key) { $page.Visibility = 'Visible' }
            else { $page.Visibility = 'Collapsed' }
        }
    }
    $script:CurrentPage = $Key
    Set-ActiveNav -Key $Key
    if ($Key -eq 'Security') { Refresh-SecurityReport }
}

function Update-Sparkline {
    param($Samples, $Line, [int]$Max = 100)
    if (-not $Line) { return }
    $n = @($Samples).Count
    if ($n -lt 2) { $Line.Points = New-Object System.Windows.Media.PointCollection; return }
    $pts = New-Object System.Windows.Media.PointCollection
    $w = 84.0
    $h = 24.0
    $step = $w / ($n - 1)
    $maxV = [double]$Max
    foreach ($v in $Samples) { if ([double]$v -gt $maxV) { $maxV = [double]$v } }
    if ($maxV -le 0) { $maxV = 1 }
    for ($i = 0; $i -lt $n; $i++) {
        $x = [double]$i * $step
        $y = $h - (([double]$Samples[$i] / $maxV) * ($h - 2)) - 1
        [void]$pts.Add((New-Object System.Windows.Point($x, $y)))
    }
    $Line.Points = $pts
}

$script:StatBusy = $false
$script:SamplesCpu = New-Object 'System.Collections.Generic.List[double]'
$script:SamplesRam = New-Object 'System.Collections.Generic.List[double]'
$script:SamplesDisk = New-Object 'System.Collections.Generic.List[double]'

function Add-StatSample {
    param($List, [double]$Value)
    [void]$List.Add($Value)
    if ($List.Count -gt 28) { $List.RemoveAt(0) }
}

function Update-HomeStats {
    if ($script:StatBusy) { return }
    $script:StatBusy = $true
    try {
        $cpu = $null
        try {
            $p = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
            if ($p -and ($p.PercentProcessorTime -ne $null)) { $cpu = [double]$p.PercentProcessorTime }
        } catch { }
        if ($cpu -eq $null) {
            try {
                $pr = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | ForEach-Object { [double]$_.LoadPercentage })
                if ($pr.Count -gt 0) { $cpu = [double]((($pr | Measure-Object -Average).Average)) }
            } catch { }
        }
        if ($cpu -eq $null) {
            try {
                $cs = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop
                if ($cs -and $cs.CounterSamples -and ($cs.CounterSamples.Count -gt 0)) { $cpu = [double]$cs.CounterSamples[0].CookedValue }
            } catch { }
        }
        if ($cpu -ne $null) {
            if ($cpu -lt 0) { $cpu = 0 }
            if ($cpu -gt 100) { $cpu = 100 }
            Add-StatSample -List $script:SamplesCpu -Value $cpu
            if ($script:TxtStatCpu) { $script:TxtStatCpu.Text = ([int][math]::Round($cpu, 0)).ToString() + '%' }
            if ($script:PgStatCpu) { $script:PgStatCpu.Value = $cpu }
            Update-Sparkline -Samples $script:SamplesCpu -Line $script:SpCpu -Max 100
        }
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $totalKb = [double]$os.TotalVisibleMemorySize
            $freeKb = [double]$os.FreePhysicalMemory
            if ($totalKb -gt 0) {
                $ramPct = [math]::Round((($totalKb - $freeKb) / $totalKb) * 100, 0)
                Add-StatSample -List $script:SamplesRam -Value $ramPct
                if ($script:TxtStatRam) { $script:TxtStatRam.Text = ([int]$ramPct).ToString() + '%' }
                if ($script:PgStatRam) { $script:PgStatRam.Value = $ramPct }
                Update-Sparkline -Samples $script:SamplesRam -Line $script:SpRam -Max 100
            }
        } catch { }
        try {
            $d = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
            if ($d -and ([double]$d.Size -gt 0)) {
                $diskPct = [math]::Round((([double]$d.Size - [double]$d.FreeSpace) / [double]$d.Size) * 100, 0)
                Add-StatSample -List $script:SamplesDisk -Value $diskPct
                if ($script:TxtStatDisk) { $script:TxtStatDisk.Text = ([int]$diskPct).ToString() + '%' }
                if ($script:PgStatDisk) { $script:PgStatDisk.Value = $diskPct }
                Update-Sparkline -Samples $script:SamplesDisk -Line $script:SpDisk -Max 100
            }
        } catch { }
    } finally {
        $script:StatBusy = $false
    }
}

function Set-HealthShield {
    param([bool]$Ok)
    if (-not $script:BrdHealthShield) { return }
    if ($Ok) {
        $script:BrdHealthShield.Background = $script:BrHealthGreenBg
        $script:BrdHealthShield.BorderBrush = $script:BrHealthGreenBorder
        if ($script:TxtHealthIcon) { $script:TxtHealthIcon.Foreground = $script:BrGreen }
        $fx = New-Object System.Windows.Media.Effects.DropShadowEffect
        $fx.Color = [System.Windows.Media.ColorConverter]::ConvertFromString('#FF34D399')
        $fx.BlurRadius = 30
        $fx.ShadowDepth = 0
        $fx.Opacity = 0.45
        $script:BrdHealthShield.Effect = $fx
    } else {
        $script:BrdHealthShield.Background = $script:BrHealthAmberBg
        $script:BrdHealthShield.BorderBrush = $script:BrHealthAmberBorder
        if ($script:TxtHealthIcon) { $script:TxtHealthIcon.Foreground = $script:BrAmber }
        $fx2 = New-Object System.Windows.Media.Effects.DropShadowEffect
        $fx2.Color = [System.Windows.Media.ColorConverter]::ConvertFromString('#FFFFC66D')
        $fx2.BlurRadius = 30
        $fx2.ShadowDepth = 0
        $fx2.Opacity = 0.45
        $script:BrdHealthShield.Effect = $fx2
    }
}

function Update-HomeHealth {
    $issues = New-Object System.Collections.Generic.List[string]
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp) {
            if ($mp.RealTimeProtectionEnabled -eq $false) { [void]$issues.Add('Real-time protection is off') }
            if ($mp.AntivirusSignatureAge -ne $null) {
                $age = [int]$mp.AntivirusSignatureAge
                if (($age -gt 7) -and ($age -lt 1000)) { [void]$issues.Add('Defender signatures are ' + $age + ' days old') }
            }
        }
    } catch { }
    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($fp in @($fw)) {
            if ($fp.Enabled -eq $false) { [void]$issues.Add('A firewall profile is disabled'); break }
        }
    } catch { }
    try {
        $d = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
        if ($d -and ([double]$d.Size -gt 0)) {
            $freeGb = [math]::Round([double]$d.FreeSpace / 1GB, 1)
            if ($freeGb -lt 10) { [void]$issues.Add('Low disk space: only ' + $freeGb + ' GB free on C:') }
        }
    } catch { }
    if ($issues.Count -eq 0) {
        if ($script:TxtHealthTitle) { $script:TxtHealthTitle.Text = 'Your PC is in great shape' }
        if ($script:TxtHealthTitle) { $script:TxtHealthTitle.Foreground = $script:BrGreen }
        if ($script:TxtHealthSub) { $script:TxtHealthSub.Text = 'No problems found - Defender, firewall and disk space all look good.' }
        Set-HealthShield $true
    } else {
        if ($script:TxtHealthTitle) { $script:TxtHealthTitle.Text = 'A few things need attention' }
        if ($script:TxtHealthTitle) { $script:TxtHealthTitle.Foreground = $script:BrAmber }
        if ($script:TxtHealthSub) { $script:TxtHealthSub.Text = ($issues.ToArray() -join '.  ') + '.' }
        Set-HealthShield $false
    }
}

$script:HomeTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:HomeTimer.Interval = [TimeSpan]::FromMilliseconds(2500)
$script:HomeTimer.Add_Tick({
    if ($script:DlgDepth -gt 0) { return }
    if ($script:CurrentPage -eq 'Home') { Update-HomeStats }
})

$script:FilterTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:FilterTimer.Interval = [TimeSpan]::FromMilliseconds(350)
$script:FilterTimer.Add_Tick({
    $script:FilterTimer.Stop()
    if ($script:DlgDepth -gt 0) { $script:FilterTimer.Start(); return }
    Refresh-TweakStatuses
})

$script:AppFilterTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:AppFilterTimer.Interval = [TimeSpan]::FromMilliseconds(300)
$script:AppFilterTimer.Add_Tick({
    $script:AppFilterTimer.Stop()
    Build-AppRows
})

$script:UninstallFilterTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:UninstallFilterTimer.Interval = [TimeSpan]::FromMilliseconds(300)
$script:UninstallFilterTimer.Add_Tick({
    $script:UninstallFilterTimer.Stop()
    Update-UninstallList
})

$script:StatusTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:StatusTimer.Interval = [TimeSpan]::FromMilliseconds(40)
$script:StatusTimer.Add_Tick({
    $script:StatusTimer.Stop()
    if ($script:DlgDepth -gt 0) { $script:StatusTimer.Start(); return }
    if (-not $script:StatusKeys -or $script:StatusKeys.Count -eq 0) { return }
    if ($script:StatusIndex -ge $script:StatusKeys.Count) { return }
    $end = [int]$script:StatusIndex + 5
    if ($end -gt $script:StatusKeys.Count) { $end = $script:StatusKeys.Count }
    while ($script:StatusIndex -lt $end) {
        Update-TweakStatusRow -Key ([string]$script:StatusKeys[$script:StatusIndex])
        $script:StatusIndex = [int]$script:StatusIndex + 1
    }
    if ($script:StatusIndex -ge $script:StatusKeys.Count) {
        Update-TweakInfoLine
    } else {
        if ($script:TxtTweakInfo) { $script:TxtTweakInfo.Text = ('Refreshing statuses...  ' + $script:StatusIndex + '/' + $script:StatusKeys.Count) }
        $script:StatusTimer.Start()
    }
})

function Initialize-STweakUI {
    Write-Log 'STweak v2 started.'
    $script:CmbPreset.Items.Clear()
    foreach ($name in @($Presets.Keys | Sort-Object)) { [void]$script:CmbPreset.Items.Add($name) }
    if ($script:CmbPreset.Items.Count -gt 0) { $script:CmbPreset.SelectedIndex = 0 }
    $script:CmbTweakCategory.Items.Clear()
    [void]$script:CmbTweakCategory.Items.Add('All')
    foreach ($c in @($TweakCatalog | ForEach-Object { $_.Category } | Select-Object -Unique | Sort-Object)) { [void]$script:CmbTweakCategory.Items.Add($c) }
    $script:CmbTweakCategory.SelectedItem = 'All'
    $script:CmbAppCategory.Items.Clear()
    [void]$script:CmbAppCategory.Items.Add('All')
    foreach ($c in @($AppCatalog | ForEach-Object { $_.Category } | Select-Object -Unique | Sort-Object)) { [void]$script:CmbAppCategory.Items.Add($c) }
    $script:CmbAppCategory.SelectedItem = 'All'
    Build-TweakRows
    Refresh-TweakStatuses
    Build-AppRows
    Load-InstalledPrograms
    Refresh-History
    Refresh-QuarantineView
    $hour = (Get-Date).Hour
    $greet = 'Hello'
    if ($hour -lt 5) { $greet = 'Working late' }
    elseif ($hour -lt 12) { $greet = 'Good morning' }
    elseif ($hour -lt 18) { $greet = 'Good afternoon' }
    else { $greet = 'Good evening' }
    $disp = [string][Environment]::UserName
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs -and $cs.UserName) {
            $parts = [string]$cs.UserName -split '\\'
            if ($parts.Count -ge 2) { $disp = $parts[1] }
        }
    } catch { }
    $script:TxtGreeting.Text = ($greet + ', ' + $disp)
    $script:TxtHomeDate.Text = (Get-Date).ToString('dddd, d MMMM yyyy')
    $script:TxtHomeTagline.Text = 'Tweaks, apps, cleanup and deep uninstall - all in one window.'
    Show-Page 'Home'
    Update-HomeHealth
    Update-HomeStats
    $script:HomeTimer.Start()
    $script:WingetOk = Test-WinGetAvailable
    if ($script:WingetOk) {
        Write-Log 'winget detected - install and update features are enabled.'
        Start-WingetListRefresh
    } else {
        Write-Log 'winget NOT found - install and update features are disabled.'
        $script:BtnInstallSelected.IsEnabled = $false
        $script:BtnRefreshWinget.IsEnabled = $false
        $script:BtnScanUpgrades.IsEnabled = $false
        $script:BtnUpgradeSelected.IsEnabled = $false
        $script:TxtUpgradeInfo.Text = 'winget is not available on this system.'
    }
}

function Wire-EventHandlers {
    $script:TxtAppSearch.Add_TextChanged({
        $script:AppFilterTimer.Stop()
        $script:AppFilterTimer.Start()
    })
    $script:CmbAppCategory.Add_SelectionChanged({ Build-AppRows })
    $script:ChkAppsInstalledOnly.Add_Click({ Build-AppRows })
    $script:BtnRefreshWinget.Add_Click({
        if ($script:BgJob) { Show-Info 'Another operation is still running. Wait for it to finish.'; return }
        if (-not $script:WingetOk) { Show-Err 'winget is not available on this system.'; return }
        Start-WingetListRefresh
    })
    $script:BtnInstallSelected.Add_Click({ Install-AppsSelected })
    $script:BtnScanUpgrades.Add_Click({ Scan-Upgrades })
    $script:BtnUpgradeSelected.Add_Click({ Upgrade-AppsSelected })

    $script:TxtTweakSearch.Add_TextChanged({
        Build-TweakRows
        $script:FilterTimer.Stop()
        $script:FilterTimer.Start()
    })
    $script:CmbTweakCategory.Add_SelectionChanged({
        Build-TweakRows
        $script:FilterTimer.Stop()
        $script:FilterTimer.Start()
    })
    $script:BtnCheckTweaks.Add_Click({ Refresh-TweakStatuses })
    $script:BtnApplyPreset.Add_Click({ Apply-CurrentPreset })
    $script:BtnApplyTweaks.Add_Click({ Apply-TweaksSelected })
    $script:BtnRevertTweaks.Add_Click({ Revert-TweaksSelected })

    $script:TxtUninstallFilter.Add_TextChanged({
        $script:UninstallFilterTimer.Stop()
        $script:UninstallFilterTimer.Start()
    })
    $script:BtnLoadPrograms.Add_Click({ Load-InstalledPrograms })
    $script:BtnDeepScan.Add_Click({ Start-DeepScan -Manual $false })
    $script:BtnScanManual.Add_Click({ Start-DeepScan -Manual $true })
    $script:LstUninstallPrograms.Add_MouseDoubleClick({
        if ($script:LstUninstallPrograms.SelectedIndex -ge 0) { Start-DeepScan -Manual $false }
    })

    $script:BtnAnalyzeCleanup.Add_Click({ Invoke-CleanupAnalyze })
    $script:BtnRunCleanup.Add_Click({ Start-CleanupRunning })

    $script:BtnLoadAppx.Add_Click({ Load-AppxPackages })
    $script:BtnRemoveAppx.Add_Click({ Remove-SelectedAppx })

    $script:BtnRefreshSecurity.Add_Click({ Refresh-SecurityReport })
    $script:BtnSecOpenDefender.Add_Click({
        try { Start-Process 'windowsdefender:' } catch { Show-Err ('Could not open Windows Security: ' + $_.Exception.Message) 'Security' }
    })
    $script:BtnSecUpdateDefs.Add_Click({ Start-DefenderAction -Action 'update' -Title 'Updating Defender signatures...' -ConfirmText '' })
    $script:BtnSecQuickScan.Add_Click({ Start-DefenderAction -Action 'quick' -Title 'Running a Defender quick scan...' -ConfirmText 'Run a quick antivirus scan now?' })
    $script:BtnSecFullScan.Add_Click({ Start-DefenderAction -Action 'full' -Title 'Running a Defender full scan...' -ConfirmText 'Run a full antivirus scan now? This can take a long time.' })

    $script:BtnRefreshHistory.Add_Click({ Refresh-History })
    $script:BtnUndoAllTweaks.Add_Click({ Undo-AllAppliedTweaks })

    $script:BtnRefreshQuarantine.Add_Click({ Refresh-QuarantineView })
    $script:BtnOpenQuarantineFolder.Add_Click({
        try { Start-Process explorer.exe -ArgumentList $QuarantineDir } catch { }
    })

    $script:BtnOpenTextLog.Add_Click({
        if (Test-Path -LiteralPath $TextLogFile) { Start-Process notepad.exe -ArgumentList $TextLogFile }
        else { Show-Info 'The log file has not been created yet.' }
    })
    $script:BtnOpenDataFolder.Add_Click({
        try { Start-Process explorer.exe -ArgumentList $RootDir } catch { }
    })
    $script:BtnClearActivityLog.Add_Click({ $script:TxtActivityLog.Clear() })

    $script:BtnCancelJob.Add_Click({
        if (-not $script:BgJob) { return }
        if (Ask-YesNo 'Stop the running operation?' 'STweak') {
            try { Stop-Job -Job $script:BgJob -ErrorAction SilentlyContinue } catch { }
            Write-Log 'Stop was requested for the running operation.'
        }
    })

    foreach ($navKey in @($script:NavMap.Keys)) {
        $navBtn = $script:Window.FindName($script:NavMap[$navKey])
        if ($navBtn) {
            $target = $navKey
            $navBtn.Add_Click({ Show-Page $target }.GetNewClosure())
        }
    }
    $script:BtnQuickClean.Add_Click({ Show-Page 'Cleanup' })
    $script:BtnQuickApps.Add_Click({ Show-Page 'Apps' })
    $script:BtnQuickTweaks.Add_Click({ Show-Page 'Tweaks' })
    $script:BtnQuickUninstall.Add_Click({ Show-Page 'Uninstall' })
    $script:BtnQuickHistory.Add_Click({ Show-Page 'History' })
    $script:BtnQuickSecurity.Add_Click({ Show-Page 'Security' })
    $script:BtnBannerTweaks.Add_Click({ Show-Page 'Tweaks' })
    $script:BtnHomeRunCleaner.Add_Click({
        Show-Page 'Cleanup'
        Invoke-CleanupAnalyze
    })
    $script:BtnHomeDetails.Add_Click({
        Show-Page 'Security'
        Update-HomeHealth
    })

    $script:Window.Add_Closing({
        param($sender, $ev)
        if ($script:ClosingOk) { return }
        if ($script:BgJob) {
            $ev.Cancel = $true
            if (Ask-YesNo 'A background operation is still running. Stop it and exit?' 'Exit STweak') {
                try { Stop-Job -Job $script:BgJob -ErrorAction SilentlyContinue } catch { }
                try { Remove-Job -Job $script:BgJob -Force -ErrorAction SilentlyContinue } catch { }
                $script:BgJob = $null
                $script:ClosingOk = $true
                $script:Window.Close()
            }
        }
    })
}

function Invoke-DoEvents {
    $frame = New-Object System.Windows.Threading.DispatcherFrame
    $cb = [System.Windows.Threading.DispatcherOperationCallback]{
        param($f)
        $f.Continue = $false
        return $null
    }
    $null = [System.Windows.Threading.Dispatcher]::CurrentDispatcher.BeginInvoke(
        [System.Windows.Threading.DispatcherPriority]::Background, $cb, $frame)
    [System.Windows.Threading.Dispatcher]::PushFrame($frame)
}

if ($ValidateOnly) {
    $fails = New-Object System.Collections.Generic.List[string]
    $nl = [Environment]::NewLine

    if (-not $script:Window) {
        [void]$fails.Add('the main window was not created')
    } else {
        foreach ($pk in @($script:PageMap.Keys)) {
            if (-not $script:Window.FindName($script:PageMap[$pk])) { [void]$fails.Add('page was not found: ' + $script:PageMap[$pk]) }
        }
        if ($script:PageMap.Count -ne 10) { [void]$fails.Add('expected 10 pages, found ' + $script:PageMap.Count) }
    }

    foreach ($n in $refNames) {
        $v = Get-Variable -Name $n -Scope Script -ErrorAction SilentlyContinue
        if (-not $v -or -not $v.Value) { [void]$fails.Add('control reference is missing: ' + $n) }
    }

    $bodyChecks = @(
        @{ Name = 'WorkerSrc';           Text = $WorkerSrc }
        @{ Name = 'UninstallScanBody';   Text = $UninstallScanBody }
        @{ Name = 'WingetListBody';      Text = $WingetListBody }
        @{ Name = 'UpgradeScanBody';     Text = $UpgradeScanBody }
        @{ Name = 'InstallBody';         Text = $InstallBody }
        @{ Name = 'UpgradeBody';         Text = $UpgradeBody }
        @{ Name = 'CleanupBody';         Text = $CleanupBody }
        @{ Name = 'AppxBody';            Text = $AppxBody }
        @{ Name = 'DefenderBody';        Text = $DefenderBody }
        @{ Name = 'WingetUninstallBody'; Text = $WingetUninstallBody }
    )
    foreach ($bc in $bodyChecks) {
        try { $null = [scriptblock]::Create($WorkerSrc + $nl + $bc.Text) }
        catch { [void]$fails.Add($bc.Name + ' does not compile: ' + $_.Exception.Message) }
    }

    if ($TweakCatalog.Count -lt 40) { [void]$fails.Add('the tweak catalog looks too small: ' + $TweakCatalog.Count) }
    $keys = @{}
    foreach ($t in $TweakCatalog) {
        if ($keys.ContainsKey($t.Key)) { [void]$fails.Add('duplicate tweak key: ' + $t.Key) }
        else { $keys[$t.Key] = 1 }
    }
    $ids = @{}
    foreach ($a in $AppCatalog) {
        if ($ids.ContainsKey($a.Id)) { [void]$fails.Add('duplicate app id: ' + $a.Id) }
        else { $ids[$a.Id] = 1 }
    }
    foreach ($p in $Presets.Keys) {
        foreach ($k in @($Presets[$p])) {
            if (-not $keys.ContainsKey($k)) { [void]$fails.Add('preset ' + $p + ' references an unknown tweak: ' + $k) }
        }
    }

    $r1 = [string](ConvertTo-PSRegPath 'HKCU\Software\Microsoft')
    if ($r1 -ne 'HKCU:\Software\Microsoft') { [void]$fails.Add('ConvertTo-PSRegPath produced: ' + $r1) }
    $r2 = [string](ConvertTo-PSRegPath 'HKLM\SOFTWARE\Whatever')
    if ($r2 -ne 'HKLM:\SOFTWARE\Whatever') { [void]$fails.Add('ConvertTo-PSRegPath produced: ' + $r2) }
    $h = ConvertTo-HashtableDeep $null
    if ($h -isnot [hashtable]) { [void]$fails.Add('ConvertTo-HashtableDeep(null) did not return a hashtable') }
    $m = @(Get-AppMatchers -DisplayName 'Contoso Widget Pro Edition' -Publisher 'Contoso Labs')
    if ($m.Count -eq 0) { [void]$fails.Add('Get-AppMatchers returned no name patterns') }
    $sf = Test-SafeLeftoverPath 'C:\Windows'
    if (-not $sf -or ($sf.Safe -eq $true)) { [void]$fails.Add('Test-SafeLeftoverPath treats C:\Windows as a safe cleanup path') }

    Initialize-ReviewDialog
    if (-not $script:RevDlg) { [void]$fails.Add('the review dialog did not load') }
    else {
        foreach ($n in @('SpRevPanel','TxtRevHeader','TxtRevSub','TxtRevConfirm','TxtRevStatus','BtnRevExecute','RbQuarantine','RbDelete','RbRecycle','BtnRevCancel','BtnRevAll','BtnRevNone')) {
            if (-not $script:RevDlg.FindName($n)) { [void]$fails.Add('review dialog control missing: ' + $n) }
        }
    }
    Initialize-ConfirmDialog
    if (-not $script:CfDlg) { [void]$fails.Add('the confirm dialog did not load') }
    else {
        foreach ($n in @('TxtCfTitle','TxtCfNotes','TxtCfLines','BtnCfOk','BtnCfCancel')) {
            if (-not $script:CfDlg.FindName($n)) { [void]$fails.Add('confirm dialog control missing: ' + $n) }
        }
    }

    $script:ValJobDone = $false
    $script:ValState = ''
    $script:ValData = $null
    $valBody = @'
W('validation job ran')
$obj = [PSCustomObject]@{ Ok = $true; N = 42 }
[System.IO.File]::WriteAllText(($log + '.json'), ($obj | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
W('DONE')
'@
    $valDone = {
        param($result)
        $script:ValJobDone = $true
        $script:ValState = [string]$result.State
        $script:ValData = $result.Data
    }
    $started = Start-BgOperation -Kind 'selfval' -Title 'Self-test job' -Body ([scriptblock]::Create($WorkerSrc + $nl + $valBody)) -Payload $null -OnDone $valDone
    if (-not $started) {
        [void]$fails.Add('could not start the self-test job')
    } else {
        $deadline = (Get-Date).AddSeconds(40)
        while ((-not $script:ValJobDone) -and ((Get-Date) -lt $deadline)) {
            Invoke-DoEvents
            Start-Sleep -Milliseconds 50
        }
        if (-not $script:ValJobDone) {
            [void]$fails.Add('the self-test job did not finish within 40 seconds')
            try { Stop-Job -Job $script:BgJob -ErrorAction SilentlyContinue } catch { }
            try { Remove-Job -Job $script:BgJob -Force -ErrorAction SilentlyContinue } catch { }
            $script:BgJob = $null
        } elseif ($script:ValState -ne 'Completed') {
            [void]$fails.Add('the self-test job ended with state: ' + $script:ValState)
        } elseif (-not $script:ValData) {
            [void]$fails.Add('the self-test job produced no result data')
        } elseif ([int]$script:ValData['N'] -ne 42) {
            [void]$fails.Add('the self-test job result JSON is wrong')
        }
    }

    Write-Host ''
    Write-Host ('Tweaks: ' + $TweakCatalog.Count + '   Apps: ' + $AppCatalog.Count + '   Presets: ' + $Presets.Count)
    if ($fails.Count -eq 0) {
        Write-Host 'VALIDATION OK'
        exit 0
    }
    foreach ($f in $fails) { Write-Host ('FAIL: ' + $f) }
    Write-Host 'VALIDATION FAILED'
    exit 1
}

Initialize-STweakUI
Wire-EventHandlers
$script:UiPumping = $true
$script:Window.ShowDialog() | Out-Null

