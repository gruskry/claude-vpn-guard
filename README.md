# Claude VPN Guard for Windows

**Current release: v1.3.1** · [Release notes](https://github.com/gruskry/claude-vpn-guard/releases/tag/v1.3.1) · [Windows x64 installer](https://github.com/gruskry/claude-vpn-guard/releases/latest/download/ClaudeVPNGuard_Installer.exe) · [Portable ZIP](https://github.com/gruskry/claude-vpn-guard/releases/latest/download/claude-vpn-guard-windows.zip)

Claude Guard installs Windows Defender Firewall outbound block rules for discovered native Claude executables on physical network adapters. The tray and terminal launchers verify the effective rules before starting Claude. A public IP/country check is an additional launch policy; it does not prove that traffic uses a VPN.

## Requirements and scope

- Windows x64 with Windows PowerShell 5.1, .NET Framework 4.x, and Windows Defender Firewall enabled for all three profiles. Local firewall rules must be permitted by policy.
- Install Claude Desktop or a native `claude.exe` first. Run setup under the Windows account that uses Claude; administrator access is required for setup and removal.
- A VPN with a suitable virtual network adapter is needed for Claude traffic to pass the physical-adapter blocks. Compatibility must be tested with your actual VPN and routing configuration.
- New or renamed physical adapters, new executables, and application updates that change paths require running setup again. Guard blocks a new launch when current coverage is incomplete. It checks coverage periodically during a guarded session and stops identified Claude processes when verification fails.
- These checks have a delay. They cannot guarantee that no packets escape during an interface, policy, or application change. Virtual adapters, local proxy services, WSL/VMs, browsers, and external tools/child executables outside the discovered installation are outside this rule set. Package rules supplement executable rules; they are not a promise that every future update is covered.
- This project does not guarantee account eligibility, anonymity, or prevention of account restrictions. Country blocking is a local policy in `guard-runtime.ps1`.

## Install and use

Download and run `ClaudeVPNGuard_Installer.exe` from the latest release. If building locally, the installer is written to `Output\ClaudeVPNGuard_Installer.exe`. Firewall setup must succeed before installation proceeds. Failed setup retains the previous rules and reports an error.

For the portable package, extract the entire ZIP to a trusted folder, run `setup-firewall.cmd`, then start `Claude (VPN Guard).exe` or `launch-guarded.cmd`. Keep the helper scripts beside the executable. The terminal launcher requires a native `claude.exe` on PATH:

```cmd
launch-cli-guarded.cmd -p "Explain this project"
```

Arguments and the CLI exit code are preserved. Node/npm command wrappers are not launched; install a native Claude Code binary on PATH instead.

To inspect the current rules without modifying Windows settings:

```powershell
powershell.exe -NoProfile -File .\check-protection.ps1
```

The tray status command uses this same verification. A firewall log line has no reliable application attribution, so the tray no longer labels unrelated dropped packets as Claude leaks. Close Claude to end the session; the launcher remains running until then.

## Claude updates and changed paths

Guard rediscovers Claude before every guarded launch and approximately every five seconds after each completed check during a session. Discovery covers the installed Claude MSIX package, the known Claude folders under `%LOCALAPPDATA%` and `%APPDATA%`, native CLI installation paths, and `claude.exe` on PATH. It does not search arbitrary custom Desktop installation folders.

**Detection is automatic; firewall rule updates are manual in v1.3.1.** If an update introduces a new executable path without an effective rule, Guard refuses a new launch or attempts to stop identified running Claude processes. Close Claude, run `setup-firewall.cmd` again (approve the administrator prompt), then relaunch through Guard. Follow the same procedure after adding or renaming a physical adapter. This detection is periodic, not an instantaneous block for an unknown new executable.

## Upgrading from older releases

Close Claude and the previous Guard session, then install v1.3.1 or replace the entire portable folder with its new ZIP and run `setup-firewall.cmd`. Copying only the launcher EXE is insufficient: it requires the matching helper scripts. The new runtime replaces the previous setup state after verifying the new rules.

Guard does not register a replacement `claude://` handler. Browser "Open in app" actions can launch Claude directly and do not run Guard's preflight checks; only existing matching firewall rules apply to that direct launch. Use the Guard launcher for a checked session. Older releases' "zero leak", universal VPN compatibility, update immunity, and account protection promises are not guarantees of this version.

## Timezone

`config.json` supports:

```json
{
  "target_timezone": "Georgian Standard Time",
  "auto_detect": true,
  "change_timezone": true
}
```

With automatic detection, only a recognized IANA timezone is mapped to a Windows timezone. With `auto_detect: false`, `target_timezone` is used. Set `change_timezone: false` or pass `-NoTimezoneChange` to the PowerShell launcher to leave the timezone alone.

A timezone change affects the whole Windows system and requires Windows permission. Errors block launch. The original value is saved before the change in `%LOCALAPPDATA%\ClaudeVPNGuard\timezone-state.json`, restored when the session ends, and recovered on the next guarded launch after a crash. A later manual timezone change is preserved. If Guard is forcibly terminated, restoration waits until the next launch. Do not delete recovery state while troubleshooting. Guard preserves application storage and authentication data.

## Optional DNS-over-HTTPS

`enable-dns-leak-protection.cmd` changes system DNS settings for physical adapters and enforces configured DoH templates. This affects other applications as well. It requires a Windows build with the DNS Client DoH commands and compatible network policy. DoH encrypts supported DNS transport; it is not proof that all application DNS or network traffic uses the VPN.

The script saves original IPv4/IPv6 DNS settings and DoH templates before applying changes. Any failed step reports failure and attempts rollback. Recovery state is in `%ProgramData%\ClaudeVPNGuard\dns-state.json`. Use `restore-dns.cmd` to restore it. Manual changes or missing adapters produce conflicts and retain the backup for recovery. Restore the previous setup before enabling it again.

Older releases did not save DNS backups. Their original settings cannot be reconstructed automatically; restore those manually from your network configuration.

## Remove

Close Claude, then uninstall through Windows settings or run `remove-firewall.cmd` for a portable installation. Removal restores saved DNS settings before removing Guard rules. If restoration or rule removal fails, the installer retains the application and recovery files so you can resolve the error and retry. Successfully removing the rules allows Claude to use physical interfaces directly.

## Build and regression checks

```powershell
powershell.exe -NoProfile -File .\tests\run.ps1
powershell.exe -NoProfile -File .\build.ps1
```

The build requires the .NET Framework C# compiler and Inno Setup 6. Use `-InnoCompiler "C:\path\ISCC.exe"` for a different installation path. It rebuilds the tray EXE, installer, and portable ZIP, then compares archived file hashes with the current files. Generated artifacts are unsigned.

The regression suites replace network/administration boundaries with test doubles and use temporary files for timezone and native argument checks. They do not change the machine's firewall, DNS, or timezone. Before distributing a release, separately test installation/removal and actual IPv4/IPv6 traffic with your supported VPNs, including disconnection, reconnect, adapter changes, app updates, static/DHCP DNS, and denied administrative permission. Compilation and mocked tests do not establish those live-network guarantees.
