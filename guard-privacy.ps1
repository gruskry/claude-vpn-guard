#Requires -Version 5.1
param([switch]$Clean,[switch]$Json,[string]$RestoreBackup)
. "$PSScriptRoot\guard-common.ps1"
function Assert-GuardPrivateFilePath([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Privacy data and backup paths must not contain links or junctions.' }
        }
        $parent=Split-Path $current -Parent
        if ($parent -eq $current) { break }
        $current=$parent
    }
}
function Get-GuardDiagnosticFiles {
    # Only confirmed Sentry scope stores. No recursive scan of auth/session/history.
    foreach ($directory in @(
        (Join-Path $env:APPDATA 'Claude\sentry'),
        (Join-Path $env:LOCALAPPDATA 'Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\sentry')
    )) {
        $path=Join-Path $directory 'scope_v3.json'
        if (Test-Path -LiteralPath $path -PathType Leaf) { $path }
    }
}
function Remove-GuardDiagnosticFields($Data) {
    $count=0
    foreach ($containerName in @('scope','event')) {
        $container=$Data.$containerName
        if (-not $container) { continue }
        if ($container.user -and $container.user.PSObject.Properties['ip_address']) {
            $container.user.PSObject.Properties.Remove('ip_address'); $count++
        }
        if ($container.contexts.culture -and $container.contexts.culture.PSObject.Properties['timezone']) {
            $container.contexts.culture.PSObject.Properties.Remove('timezone'); $count++
        }
        if ($container.contexts.geo) {
            foreach ($key in @('city','country_code','region','latitude','longitude')) {
                if ($container.contexts.geo.PSObject.Properties[$key]) { $container.contexts.geo.PSObject.Properties.Remove($key); $count++ }
            }
        }
    }
    $count
}
function Get-GuardByteHash([byte[]]$Bytes) {
    $hasher=[Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-','') } finally { $hasher.Dispose() }
}
function ConvertFrom-GuardDiagnosticJson([string]$Text) {
    try { $data=$Text | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Diagnostic JSON could not be parsed. Original data was retained.' }
    if ($data -isnot [pscustomobject]) { throw 'Unsupported diagnostic JSON format. Original data was retained.' }
    $data
}
function Invoke-GuardPrivacy([switch]$Clean,[string]$RestoreBackup) {
    if ($Clean -and $RestoreBackup) { throw 'Choose cleanup or backup restoration, not both.' }
    $mutex=$null; $locked=$false
    $fields=0; $cleaned=0; $files=@(Get-GuardDiagnosticFiles)
    try {
        if ($Clean -or $RestoreBackup) {
            $mutex=New-Object Threading.Mutex($false,'Global\ClaudeVPNGuard_LaunchSession')
            try { $locked=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked=$true }
            if (-not $locked) { throw 'A guarded session is running. Close Claude before cleaning diagnostics.' }
            $inventory=Get-GuardInventory
            if (@(Get-GuardRunningProcesses $inventory).Count) { throw 'Close Claude before cleaning diagnostics.' }
            Add-Type -AssemblyName System.Security
        }
        if ($RestoreBackup) {
            $backupDirectory=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'ClaudeVPNGuard\privacy-backups'))
            $backupPath=[IO.Path]::GetFullPath($RestoreBackup)
            if ((Split-Path $backupPath -Parent) -ine $backupDirectory -or (Split-Path $backupPath -Leaf) -notmatch '^[a-f0-9]{32}\.bin$') { throw 'Choose a backup from this user account privacy-backups directory.' }
            Assert-GuardPrivateFilePath $backupPath
            if ((Get-Item -LiteralPath $backupPath).Length -gt 4MB) { throw 'Privacy backup is too large.' }
            $plain=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($backupPath),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
            $saved=ConvertFrom-GuardDiagnosticJson ([Text.Encoding]::UTF8.GetString($plain))
            if ($saved.Version -ne 1 -or $files -notcontains $saved.Path -or $saved.CleanHash -notmatch '^[A-F0-9]{64}$') { throw 'Privacy backup does not identify a supported diagnostic scope.' }
            $file=[string]$saved.Path
            Assert-GuardPrivateFilePath $file
            if ((Get-GuardByteHash ([IO.File]::ReadAllBytes($file))) -cne $saved.CleanHash) { throw 'Diagnostics changed after cleanup. Restoration refused to preserve later changes.' }
            $original=[Convert]::FromBase64String($saved.Original)
            if ($original.Length -gt 2MB) { throw 'Original diagnostic scope is too large.' }
            $null=ConvertFrom-GuardDiagnosticJson ([Text.Encoding]::UTF8.GetString($original).TrimStart([char]0xFEFF))
            $temporary=$file+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
            try {
                [IO.File]::WriteAllBytes($temporary,$original)
                Assert-GuardPrivateFilePath $file
                if (@(Get-GuardRunningProcesses $inventory).Count -or (Get-GuardByteHash ([IO.File]::ReadAllBytes($file))) -cne $saved.CleanHash) { throw 'Claude or diagnostics changed during restoration. Current data retained.' }
                [IO.File]::Replace($temporary,$file,[NullString]::Value)
            } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
            return [pscustomobject]@{Files=1;Fields=0;Cleaned=0;Restored=$true}
        }
        foreach ($file in $files) {
            Assert-GuardPrivateFilePath $file
            if ((Get-Item -LiteralPath $file).Length -gt 2MB) { throw 'Diagnostic scope is too large for safe automatic cleanup.' }
            $original=[IO.File]::ReadAllBytes($file)
            $text=[Text.Encoding]::UTF8.GetString($original).TrimStart([char]0xFEFF)
            $data=ConvertFrom-GuardDiagnosticJson $text
            $removed=Remove-GuardDiagnosticFields $data
            $fields+=$removed
            if (-not $Clean -or -not $removed) { continue }
            $backupDirectory=Join-Path $env:LOCALAPPDATA 'ClaudeVPNGuard\privacy-backups'
            Assert-GuardPrivateFilePath $backupDirectory
            New-Item -ItemType Directory -Path $backupDirectory -Force -ErrorAction Stop | Out-Null
            $backup=Join-Path $backupDirectory ([guid]::NewGuid().ToString('N')+'.bin')
            $updated=$data | ConvertTo-Json -Depth 100
            $null=ConvertFrom-GuardDiagnosticJson $updated
            $updatedBytes=(New-Object Text.UTF8Encoding($false)).GetBytes($updated)
            $envelope=[pscustomobject]@{Version=1;Path=$file;CleanHash=(Get-GuardByteHash $updatedBytes);Original=[Convert]::ToBase64String($original)} | ConvertTo-Json -Compress
            $encrypted=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($envelope),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
            [IO.File]::WriteAllBytes($backup,$encrypted)
            $temporary=$file+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
            try {
                [IO.File]::WriteAllBytes($temporary,$updatedBytes)
                Assert-GuardPrivateFilePath $file
                if (@(Get-GuardRunningProcesses $inventory).Count) { throw 'Claude started during cleanup. Original diagnostics retained.' }
                if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($file)) -cne [Convert]::ToBase64String($original)) { throw 'Diagnostics changed during cleanup. Original file retained.' }
                [IO.File]::Replace($temporary,$file,[NullString]::Value)
                $cleaned++
            } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction Stop } }
        }
        [pscustomobject]@{Files=$files.Count;Fields=$fields;Cleaned=$cleaned;Scope='Known Sentry scope metadata only; queued events, logs, conversations and auth are preserved.'}
    } finally {
        if ($mutex) { if ($locked) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
    }
}
if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference='Stop'
    [Console]::OutputEncoding=[Text.Encoding]::UTF8
    try {
        $result=Invoke-GuardPrivacy -Clean:$Clean -RestoreBackup $RestoreBackup
        if ($Json) { $result | ConvertTo-Json -Compress } else { $result | Format-List }
        exit 0
    } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
