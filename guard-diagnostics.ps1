function Write-GuardDiagnosticEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidateSet('refresh-requested','refresh-verified','privacy-cleaned','desktop-started','cli-started','session-ended','launch-blocked','shutdown-failed')][string]$Event,
        [ValidateRange(0,65536)][int]$Count=0
    )
    if (-not $script:GuardDiagnosticLoggingEnabled) { return }
    try {
        $directory=Join-Path $env:LOCALAPPDATA 'ClaudeVPNGuard'
        $path=Join-Path $directory 'guard-events.jsonl'
        Assert-GuardPrivateFilePath $path
        Assert-GuardPrivateFilePath ($path+'.previous')
        New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
        if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -ge 64KB) { Move-Item -LiteralPath $path -Destination ($path+'.previous') -Force -ErrorAction Stop }
        # No free-form exception text, IP, country, path, credentials or CLI arguments.
        $entry=[pscustomobject]@{Utc=[DateTime]::UtcNow.ToString('o');Event=$Event;Count=$Count} | ConvertTo-Json -Compress
        [IO.File]::AppendAllText($path,$entry+[Environment]::NewLine,(New-Object Text.UTF8Encoding($false)))
    } catch { Write-Warning 'The diagnostic event could not be saved.' }
}
