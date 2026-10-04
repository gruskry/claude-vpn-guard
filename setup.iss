[Setup]
AppName=Claude VPN Guard
AppVersion=1.2.0
AppPublisher=Dzmitry Danilau (gruskry)
AppPublisherURL=https://github.com/gruskry/claude-vpn-guard
DefaultDirName={autopf}\Claude VPN Guard
DefaultGroupName=Claude VPN Guard
OutputBaseFilename=ClaudeVPNGuard_Installer
Compression=lzma2/ultra64
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
SetupIconFile=assets\claude.ico
UninstallDisplayIcon={app}\Claude (VPN Guard).exe

[Files]
Source: "Claude (VPN Guard).exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "config.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "setup-firewall.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "remove-firewall.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "enable-dns-leak-protection.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "enable-dns-leak-protection.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autodesktop}\Claude (VPN Guard)"; Filename: "{app}\Claude (VPN Guard).exe"; IconFilename: "{app}\assets\claude.ico"
Name: "{group}\Claude (VPN Guard)"; Filename: "{app}\Claude (VPN Guard).exe"
Name: "{group}\Uninstall Claude VPN Guard"; Filename: "{uninstallexe}"

[Registry]
; Intercept claude:// URL Scheme
Root: HKCR; Subkey: "claude"; ValueType: string; ValueName: ""; ValueData: "URL:Claude Protocol"; Flags: uninsdeletekey
Root: HKCR; Subkey: "claude"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""; Flags: uninsdeletekey
Root: HKCR; Subkey: "claude\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Claude (VPN Guard).exe"" ""%1"""; Flags: uninsdeletekey

[Run]
; Run firewall setup script silently after installation
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\setup-firewall.ps1"""; StatusMsg: "Configuring Windows Defender Firewall..."; Flags: runhidden waituntilterminated

[UninstallRun]
; Remove firewall rules during uninstallation
Filename: "{app}\remove-firewall.cmd"; Flags: runhidden waituntilterminated
