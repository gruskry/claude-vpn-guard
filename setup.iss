[Setup]
AppName=Claude VPN Guard
AppVersion=1.4.0
VersionInfoVersion=1.4.0.0
AppPublisher=Dzmitry Danilau (gruskry)
AppPublisherURL=https://github.com/gruskry/claude-vpn-guard
DefaultDirName={autopf}\Claude VPN Guard
DefaultGroupName=Claude VPN Guard
OutputBaseFilename=ClaudeVPNGuard_Installer
Compression=lzma2/ultra64
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
ArchitecturesAllowed=x64compatible
PrivilegesRequired=admin
AppMutex=Global\ClaudeVPNGuard_LaunchSession
SetupIconFile=assets\claude.ico
UninstallDisplayIcon={app}\Claude (VPN Guard).exe
#ifdef SignArtifacts
SignTool=guard-sign
SignedUninstaller=yes
#endif

[Files]
Source: "Claude (VPN Guard).exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "config.json"; DestDir: "{app}"; Flags: onlyifdoesntexist
Source: "setup-firewall.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "guard-common.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "guard-network.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "guard-privacy.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "guard-diagnostics.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "guard-runtime.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "check-protection.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "sync-guard.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "launch-cli.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "launch-guarded.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "launch-cli-guarded.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "setup-firewall.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "restore-dns.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "remove-firewall.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "enable-dns-leak-protection.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "enable-dns-leak-protection.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autodesktop}\Claude (VPN Guard)"; Filename: "{app}\Claude (VPN Guard).exe"; IconFilename: "{app}\assets\claude.ico"
Name: "{group}\Claude (VPN Guard)"; Filename: "{app}\Claude (VPN Guard).exe"
Name: "{group}\Claude Code (VPN Guard)"; Filename: "{app}\launch-cli-guarded.cmd"
Name: "{group}\Uninstall Claude VPN Guard"; Filename: "{uninstallexe}"

[Registry]
; Removed URL hijack to prevent infinite loops and Store App activation issues

[Code]
function RunGuardScript(Path, Extra: String; var ResultCode: Integer): Boolean;
begin
  Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + Path + '" -NonInteractive ' + Extra,
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  ExtractTemporaryFile('guard-common.ps1');
  ExtractTemporaryFile('guard-network.ps1');
  ExtractTemporaryFile('config.json');
  ExtractTemporaryFile('setup-firewall.ps1');
  if FileExists(ExpandConstant('{app}\config.json')) then
    if not FileCopy(ExpandConstant('{app}\config.json'), ExpandConstant('{tmp}\config.json'), False) then
    begin
      Result := 'Could not read existing Guard settings. Installation has not proceeded.';
      Exit;
    end;
  if not RunGuardScript(ExpandConstant('{tmp}\setup-firewall.ps1'), '', ResultCode) then
    Result := 'Could not start firewall setup. Installation has not proceeded.'
  else if ResultCode <> 0 then
    Result := 'Firewall setup failed (code ' + IntToStr(ResultCode) + '). Install Claude first, enable Windows Firewall and run setup-firewall.cmd to see details.'
  else
    Result := '';
end;

function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result := RunGuardScript(ExpandConstant('{app}\setup-firewall.ps1'), '-Uninstall', ResultCode);
  Result := Result and (ResultCode = 0);
  if not Result then
  begin
    Log('Guard restoration/removal failed. Files and recovery state were retained.');
    if not UninstallSilent then
      MsgBox('Could not restore DNS or remove firewall rules. Close Claude, run remove-firewall.cmd from the installation folder and retry. Recovery files were retained.', mbError, MB_OK);
  end;
end;
