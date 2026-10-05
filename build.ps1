#Requires -Version 5.1
param(
    [string]$InnoCompiler = "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    [ValidatePattern('^$|^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint='',
    [string]$SignToolPath='',
    [ValidatePattern('^https://[A-Za-z0-9./:_-]+$')][string]$TimestampUrl='https://timestamp.digicert.com'
)
$ErrorActionPreference='Stop'
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$root=$PSScriptRoot
if (-not (Test-Path -LiteralPath $compiler)) { throw '.NET Framework C# compiler is required.' }
if (-not (Test-Path -LiteralPath $InnoCompiler)) { throw 'Inno Setup 6 is required; provide -InnoCompiler with its installed path.' }
if ($CertificateThumbprint -and (-not $SignToolPath -or -not (Test-Path -LiteralPath $SignToolPath -PathType Leaf))) { throw 'Signing requires -SignToolPath and an installed code-signing certificate with its private key.' }
function Invoke-GuardArtifactSignature([string]$Path) {
    & $SignToolPath sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $Path
    if ($LASTEXITCODE -ne 0) { throw 'Artifact signing failed.' }
    & $SignToolPath verify /pa $Path
    if ($LASTEXITCODE -ne 0) { throw 'Artifact signature verification failed.' }
}
Push-Location $root
try {
    & $compiler /nologo /target:winexe /optimize+ /platform:x64 /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Web.Extensions.dll '/out:Claude (VPN Guard).exe' /win32icon:assets\claude.ico ClaudeGuard.cs
    if ($LASTEXITCODE -ne 0) { throw 'Guard compilation failed.' }
    $innoArguments=@('/Qp')
    if ($CertificateThumbprint) {
        Invoke-GuardArtifactSignature (Join-Path $root 'Claude (VPN Guard).exe')
        $resolvedSignTool=(Resolve-Path -LiteralPath $SignToolPath).Path
        $signCommand='$q'+$resolvedSignTool+'$q sign /sha1 '+$CertificateThumbprint+' /fd SHA256 /tr '+$TimestampUrl+' /td SHA256 $f'
        $innoArguments+=@('/DSignArtifacts=1',('/Sguard-sign='+$signCommand))
    }
    & $InnoCompiler @innoArguments setup.iss
    if ($LASTEXITCODE -ne 0) { throw 'Installer compilation failed.' }
    if ($CertificateThumbprint) {
        & $SignToolPath verify /pa (Join-Path $root 'Output\ClaudeVPNGuard_Installer.exe')
        if ($LASTEXITCODE -ne 0) { throw 'Installer signature verification failed.' }
    }
    $files=@('Claude (VPN Guard).exe','config.json','guard-common.ps1','guard-network.ps1','guard-privacy.ps1','guard-diagnostics.ps1','guard-runtime.ps1','check-protection.ps1','sync-guard.ps1','launch-cli.ps1','setup-firewall.ps1','setup-firewall.cmd','remove-firewall.cmd','enable-dns-leak-protection.ps1','enable-dns-leak-protection.cmd','restore-dns.cmd','launch-guarded.cmd','launch-cli-guarded.cmd','create-desktop-shortcut.ps1','create-desktop-shortcut.cmd','README.md','assets')
    $zip=Join-Path $root 'claude-vpn-guard-windows.zip'
    Compress-Archive -LiteralPath $files -DestinationPath $zip -Force
    # Check the complete archive against current files, including the executable.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive=[IO.Compression.ZipFile]::OpenRead($zip)
    try {
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName.EndsWith('/')) { continue }
            $path=Join-Path $root $entry.FullName
            $input=$entry.Open(); $hasher=[Security.Cryptography.SHA256]::Create()
            try { $hash=[BitConverter]::ToString($hasher.ComputeHash($input)).Replace('-','') } finally { $input.Dispose(); $hasher.Dispose() }
            if ($hash -ne (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash) { throw "Archive mismatch: $($entry.FullName)" }
        }
    } finally { $archive.Dispose() }
    Write-Host 'EXE, installer and portable ZIP built and archive hashes verified.'
} finally { Pop-Location }
