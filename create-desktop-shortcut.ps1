$desktop = [Environment]::GetFolderPath("Desktop")
$sh = New-Object -ComObject WScript.Shell
$lnkPath = Join-Path $desktop "Claude (VPN Guard).lnk"
$lnk = $sh.CreateShortcut($lnkPath)

$exePath = Join-Path $PSScriptRoot "Claude (VPN Guard).exe"
if (Test-Path $exePath) {
    $lnk.TargetPath = $exePath
    $lnk.IconLocation = "$exePath,0"
} else {
    $lnk.TargetPath = Join-Path $PSScriptRoot "launch-guarded.cmd"
    $icoPath = Join-Path $PSScriptRoot "assets\claude.ico"
    if (Test-Path $icoPath) { $lnk.IconLocation = "$icoPath,0" }
}

$lnk.WorkingDirectory = $PSScriptRoot
$lnk.Description = "Launch Claude Desktop with VPN Guard"
$lnk.Save()
Write-Host "`n[OK] Desktop shortcut created successfully!" -ForegroundColor Green
Write-Host "Target: $($lnk.TargetPath)" -ForegroundColor Gray
