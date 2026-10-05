<p align="center">
  <img src="assets/banner.jpg" alt="Claude VPN Guard — shield and network illustration" width="840">
</p>

<h1 align="center">Claude VPN Guard</h1>

<p align="center">
  Windows firewall checks and guarded launchers for Claude Desktop and native Claude Code.
</p>

<p align="center">
  <a href="https://github.com/gruskry/claude-vpn-guard/releases/tag/v1.3.2"><img src="https://img.shields.io/badge/release-v1.3.2-169B8A" alt="Release v1.3.2"></a>
  <img src="https://img.shields.io/badge/Windows-x64-0078D4" alt="Windows x64">
  <img src="https://img.shields.io/badge/PowerShell-5.1-5391FE" alt="Windows PowerShell 5.1">
</p>

<p align="center">
  <a href="https://github.com/gruskry/claude-vpn-guard/releases/latest/download/ClaudeVPNGuard_Installer.exe"><strong>Download installer</strong></a>
  &nbsp; · &nbsp;
  <a href="https://github.com/gruskry/claude-vpn-guard/releases/latest/download/claude-vpn-guard-windows.zip"><strong>Download portable ZIP</strong></a>
  &nbsp; · &nbsp;
  <a href="https://github.com/gruskry/claude-vpn-guard/releases/tag/v1.3.2">Release notes</a>
  &nbsp; · &nbsp;
  <a href="https://github.com/gruskry/claude-vpn-guard/releases/latest/download/SHA256SUMS.txt">SHA256 checksums</a>
</p>

---

Guard installs Windows Defender Firewall outbound block rules for discovered native Claude executables on physical network adapters. Its tray and terminal launchers verify the effective rules before starting Claude and monitor coverage during the session.

> **Claude path detection is automatic. Firewall rule updates are manual in v1.3.2.** After a new executable path or physical adapter appears, run `setup-firewall.cmd` again. See [Claude updates](#claude-updates).

[Quick start](#quick-start) · [Launchers](#launchers) · [Claude updates](#claude-updates) · [Settings](#settings) · [DNS](#optional-dns-over-https) · [Troubleshooting](#troubleshooting) · [Scope](#scope-and-limitations) · [Build](#build)

## At a glance

| Capability | What Guard does |
| --- | --- |
| **Firewall setup** | Creates outbound blocks on physical adapters and verifies new rules before replacing the previous setup. |
| **Desktop & native CLI** | Provides a tray launcher, a console launcher, and a CLI launcher that preserves arguments and exit codes. |
| **Update detection** | Rediscovers Claude executables before launch and periodically during a session. |
| **Session monitoring** | Refuses a new launch when coverage is incomplete; attempts to stop identified Claude processes if verification fails during a session. |
| **Timezone** | Optionally changes the Windows timezone and restores the previous value when the session ends. |
| **Optional DoH** | Saves and restores IPv4/IPv6 DNS settings and DNS-over-HTTPS templates. |

## Quick start

### Requirements

| Component | Requirement |
| --- | --- |
| **System** | Windows x64, Windows PowerShell 5.1, .NET Framework 4.x. |
| **Firewall** | Windows Defender Firewall enabled for all three profiles; local rules permitted by policy. |
| **Claude** | Claude Desktop or a native `claude.exe` installed before setup. |
| **VPN** | A VPN with a suitable virtual adapter; compatibility depends on its routing configuration. |
| **Permissions** | Administrator access for setup and removal. Run setup under the Windows account that uses Claude. |

### Installer

1. Install Claude and connect your VPN.
2. Download and run **[ClaudeVPNGuard_Installer.exe](https://github.com/gruskry/claude-vpn-guard/releases/latest/download/ClaudeVPNGuard_Installer.exe)**. Approve the administrator prompt.
3. Start Claude through **Claude (VPN Guard)**. Close Claude to end the monitored session.

Firewall setup must succeed before installation proceeds. Failed setup retains the previous rules and reports an error.

### Portable

1. Download the **[portable ZIP](https://github.com/gruskry/claude-vpn-guard/releases/latest/download/claude-vpn-guard-windows.zip)** and extract the entire archive to a trusted folder.
2. Run `setup-firewall.cmd` and approve the administrator prompt.
3. Start `Claude (VPN Guard).exe` or `launch-guarded.cmd`.

Keep all helper scripts beside the executable. Replacing only the EXE is insufficient.

## Launchers

| Entry point | Use |
| --- | --- |
| `Claude (VPN Guard).exe` | Launch Claude Desktop with a tray session monitor. |
| `launch-guarded.cmd` | Launch Claude Desktop with console output. |
| `launch-cli-guarded.cmd` | Run native Claude Code with your CLI arguments. |
| `check-protection.ps1` | Inspect current firewall coverage without changing Windows settings. |

**Claude Code example** — a native `claude.exe` must be on PATH:

```cmd
launch-cli-guarded.cmd -p "Explain this project"
```

Arguments and the CLI exit code are preserved. Node/npm command wrappers are not launched; use a native Claude Code binary on PATH.

**Check firewall coverage:**

```powershell
powershell.exe -NoProfile -File .\check-protection.ps1
```

The tray's **Check firewall status** command uses the same verification. The launcher stays running until Claude closes. Firewall log entries alone are not used to attribute dropped packets to Claude.

## Claude updates

Guard rediscovers Claude before every guarded launch and approximately every five seconds after each completed check during a session. It covers:

- The installed Claude MSIX package.
- Known Claude folders under `%LOCALAPPDATA%` and `%APPDATA%`.
- Native CLI installation paths and `claude.exe` on PATH.

Arbitrary custom Desktop installation folders are not searched.

**After an update changes a path, or a physical adapter is added or renamed:**

1. Close Claude.
2. Run `setup-firewall.cmd` again and approve the administrator prompt.
3. Relaunch Claude through Guard.

If a new executable lacks an effective rule, Guard refuses a new launch or attempts to stop identified running Claude processes. Detection is periodic; it is not an instantaneous block for an unknown executable.

### Upgrading Guard

Close Claude and the previous Guard session. Install **v1.3.2**, or replace the entire portable folder with the new ZIP and run `setup-firewall.cmd`. New setup state replaces the previous state only after the new rules are verified.

Version **1.3.2** fixes the `Desktop launch does not accept CLI arguments` error on a normal Desktop launch. If you see it in v1.3.1, update the complete package.

## Settings

Edit [`config.json`](config.json) in the Guard folder:

```json
{
  "target_timezone": "Georgian Standard Time",
  "auto_detect": true,
  "change_timezone": true
}
```

| Setting | Effect |
| --- | --- |
| `change_timezone` | Set to `false` to leave the Windows timezone unchanged. |
| `auto_detect` | When `true`, maps a recognized IANA timezone from the location check to a Windows timezone. |
| `target_timezone` | Windows timezone used when `auto_detect` is `false`. |

The PowerShell launcher also accepts `-NoTimezoneChange`. Guard preserves Claude's application storage and authentication data.

> Timezone changes affect the whole Windows system and require Windows permission. Errors block launch. The original value is saved before the change and restored when the session ends. After a forced termination, recovery runs on the next guarded launch. A later manual timezone change is preserved.

## Optional DNS-over-HTTPS

Run `enable-dns-leak-protection.cmd` to configure system DNS on physical adapters and enforce the configured DoH templates. Run `restore-dns.cmd` to restore the saved settings.

| Action | Command |
| --- | --- |
| Enable DoH configuration | `enable-dns-leak-protection.cmd` |
| Restore saved DNS settings | `restore-dns.cmd` |

This changes DNS settings for other applications as well and requires a Windows build with DNS Client DoH commands and compatible network policy. DoH encrypts supported DNS transport; it does not establish that all application DNS or network traffic uses the VPN.

Original IPv4/IPv6 DNS settings and DoH templates are saved before changes. A failed step reports failure and attempts rollback. Manual changes or missing adapters produce conflicts and retain the backup for recovery. Restore the previous setup before enabling it again.

Older releases did not save DNS backups. Their original settings must be restored manually from your network configuration.

## Troubleshooting

| Situation | Next step |
| --- | --- |
| **Desktop launch does not accept CLI arguments** | Update to v1.3.2. Version 1.3.1 incorrectly treated an omitted argument list as a supplied CLI argument. |
| **Coverage check fails after a Claude update** | Close Claude, run `setup-firewall.cmd`, then launch through Guard again. |
| **A physical adapter was added or renamed** | Run setup again to create matching rules for the current adapters. |
| **Firewall is disabled or local rules are rejected** | Enable all firewall profiles and resolve the local-rule policy before retrying setup. |
| **Native CLI is not found** | Install a native `claude.exe` and make it available on PATH. |
| **Timezone change is unwanted** | Set `change_timezone` to `false` in `config.json`. |
| **A helper script is missing** | Reinstall or extract the complete package. |
| **DNS restoration reports a conflict** | Resolve the reported adapter or settings conflict, preserve the backup, and retry `restore-dns.cmd`. |
| **The tray reports a session error** | Run `launch-guarded.cmd` to see the detailed error. |

<details>
<summary><strong>Recovery files</strong></summary>

| State | Location |
| --- | --- |
| Firewall setup | `%ProgramData%\ClaudeVPNGuard\firewall-state.json` |
| DNS backup | `%ProgramData%\ClaudeVPNGuard\dns-state.json` |
| Timezone recovery | `%LOCALAPPDATA%\ClaudeVPNGuard\timezone-state.json` |

Preserve these files while resolving setup or restoration errors.

</details>

## Remove

Close Claude, then uninstall through Windows settings. For a portable installation, run `remove-firewall.cmd`.

Removal restores saved DNS settings before removing Guard rules. If restoration or rule removal fails, the installer retains the application and recovery files so you can resolve the error and retry. Once the rules are removed, Claude can use physical interfaces directly.

## Scope and limitations

- **Guard is not a VPN.** A public IP/country check is an additional launch policy, not proof that traffic uses a VPN.
- **Checks have a delay.** They cannot guarantee that no packets escape during an interface, policy, or application change. Package rules supplement executable rules; future updates still require coverage verification.
- **Rules cover discovered native executables on physical adapters.** Virtual adapters, local proxy services, WSL/VMs, browsers, and external tools or child executables outside the discovered installation are outside this rule set.
- **Use the Guard launcher for a checked session.** Guard does not replace the `claude://` handler. Browser "Open in app" actions can launch Claude directly; only existing matching firewall rules apply to that launch.
- **Account eligibility and anonymity are not guaranteed.** Country blocking is a local policy in `guard-runtime.ps1`. Older releases' claims about zero leaks, universal VPN compatibility, update immunity, or account protection are not guarantees of this version.

## Build

Run the regression checks and build from the project directory:

```powershell
powershell.exe -NoProfile -File .\tests\run.ps1
powershell.exe -NoProfile -File .\build.ps1
```

The build requires the **.NET Framework C# compiler** and **Inno Setup 6**. Use `-InnoCompiler "C:\path\ISCC.exe"` for a different compiler installation path.

| Output | Artifact |
| --- | --- |
| Tray launcher | `Claude (VPN Guard).exe` |
| Installer | `Output\ClaudeVPNGuard_Installer.exe` |
| Portable archive | `claude-vpn-guard-windows.zip` |

The build rebuilds all three artifacts and compares archived file hashes with the current files. Generated artifacts are unsigned.

<details>
<summary><strong>Project structure</strong></summary>

| File | Responsibility |
| --- | --- |
| [`ClaudeGuard.cs`](ClaudeGuard.cs) | Tray interface and PowerShell session supervisor. |
| [`guard-runtime.ps1`](guard-runtime.ps1) | Shared launch, location, timezone, and monitoring logic. |
| [`guard-common.ps1`](guard-common.ps1) | Claude discovery, firewall verification, and setup state. |
| [`setup-firewall.ps1`](setup-firewall.ps1) | Firewall rule installation and removal. |
| [`enable-dns-leak-protection.ps1`](enable-dns-leak-protection.ps1) | DNS configuration, backup, and restoration. |
| [`setup.iss`](setup.iss) | Windows installer. |
| [`build.ps1`](build.ps1) | Launcher, installer, and portable archive build. |
| [`tests/`](tests/) | Regression suites. |

</details>
