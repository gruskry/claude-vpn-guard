$desktop = [Environment]::GetFolderPath("Desktop")
$sh = New-Object -ComObject WScript.Shell
$lnkPath = Join-Path $desktop "Claude (VPN Guard).lnk"
$lnk = $sh.CreateShortcut($lnkPath)
$lnk.TargetPath = Join-Path $PSScriptRoot "launch-guarded.cmd"
$lnk.WorkingDirectory = $PSScriptRoot
$icoPath = Join-Path $PSScriptRoot "assets\claude.ico"
if (Test-Path $icoPath) {
    $lnk.IconLocation = "$icoPath,0"
}
$lnk.Description = "Launch Claude Desktop with VPN Guard"
$lnk.Save()
Write-Host "`n[OK] Desktop shortcut created successfully!" -ForegroundColor Green
Write-Host "Location: $lnkPath" -ForegroundColor Gray
