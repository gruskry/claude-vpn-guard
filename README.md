<p align="center">
  <img src="assets/banner.jpg" alt="Claude VPN Guard — shield and network illustration" width="840">
</p>

<h1 align="center">Claude VPN Guard</h1>

<p align="center">
  VPN-aware firewall checks, guarded launchers and local diagnostic privacy tools for Windows.
</p>

<p align="center">
  <a href="https://github.com/gruskry/claude-vpn-guard/releases/tag/v1.4.0-rc.2"><img src="https://img.shields.io/badge/preview-v1.4.0--rc.2-D28A23" alt="Preview v1.4.0-rc.2"></a>
  <img src="https://img.shields.io/badge/Windows-x64-0078D4" alt="Windows x64">
  <img src="https://img.shields.io/badge/PowerShell-5.1-5391FE" alt="Windows PowerShell 5.1">
</p>

<p align="center">
  <a href="https://github.com/gruskry/claude-vpn-guard/releases/download/v1.4.0-rc.2/ClaudeVPNGuard_Installer.exe"><strong>Preview installer</strong></a>
  &nbsp; · &nbsp;
  <a href="https://github.com/gruskry/claude-vpn-guard/releases/download/v1.4.0-rc.2/claude-vpn-guard-windows.zip"><strong>Preview portable ZIP</strong></a>
  &nbsp; · &nbsp;
  <a href="https://github.com/gruskry/claude-vpn-guard/releases/tag/v1.4.0-rc.2">Release notes</a>
  &nbsp; · &nbsp;
  <a href="https://github.com/gruskry/claude-vpn-guard/releases/download/v1.4.0-rc.2/SHA256SUMS.txt">SHA256 checksums</a>
</p>

---

Guard detects the active internet VPN tunnel from local routes, pins its interface GUID, and installs Windows Defender Firewall outbound blocks on the other enumerated adapters for discovered native Claude executables. The tray and terminal launchers verify the tunnel and effective rules before starting Claude and monitor the session.

> **v1.4.0-rc.2 is a preview.** It introduces VPN-pinned rules and automatic refresh. Live VPN, DNS and IPv4/IPv6 acceptance is still pending. The previous stable release is [v1.3.2](https://github.com/gruskry/claude-vpn-guard/releases/tag/v1.3.2).

[Quick start](#quick-start) · [Launchers](#launchers) · [Updates](#claude-updates) · [Settings](#settings) · [Privacy](#local-diagnostic-privacy) · [DNS](#optional-dns-over-https) · [Troubleshooting](#troubleshooting) · [Scope](#scope-and-limitations) · [Build](#build)

## At a glance

| Capability | What Guard does |
| --- | --- |
| **VPN detection** | Detects a recognized virtual tunnel that owns the sampled internet routes, then saves its GUID. Later refreshes preserve that selection. |
| **Firewall setup** | Creates outbound blocks on the other enumerated physical and virtual adapters; verifies new rules before replacing the previous setup. Rules apply to both IP families. |
| **Desktop & native CLI** | Provides a tray launcher, a console launcher, and a CLI launcher that preserves arguments and exit codes. |
| **Automatic refresh** | Repairs missing coverage before launch with administrator permission and verifies it again. A running session stops on coverage failure; eligible rule changes are then refreshed for the next launch. |
| **Session monitoring** | Refuses a new launch when coverage is incomplete; attempts to stop identified Claude processes if verification fails during a session. |
| **Timezone** | Optionally changes the Windows timezone and restores the previous value when the session ends. |
| **Optional DoH** | Saves and restores IPv4/IPv6 DNS settings and DNS-over-HTTPS templates. |
| **Diagnostic privacy** | Audits and removes known IP/location fields in Sentry scope metadata while preserving auth, conversations and other settings. Backups use Windows user-bound encryption. |
| **Status & logs** | Shows the selected VPN, executable paths and blocked adapters. Saves bounded event logs containing fixed codes and counts. |

## Quick start

### Requirements

| Component | Requirement |
| --- | --- |
| **System** | Windows x64, Windows PowerShell 5.1, .NET Framework 4.x. |
| **Firewall** | Windows Defender Firewall enabled for all three profiles; local rules permitted by policy. |
| **Claude** | Claude Desktop or a native `claude.exe` installed before setup. |
| **VPN** | An active full-tunnel VPN with a virtual adapter. Recognized driver types include WireGuard/Wintun, OpenVPN/TAP, AnyConnect, NordLynx and Windows RAS tunnels. Proxy-only connections are unsupported. |
| **Permissions** | Administrator access for setup and removal. Run setup under the Windows account that uses Claude. |

### Installer

1. Install Claude and connect your VPN.
2. Download and run the **[preview installer](https://github.com/gruskry/claude-vpn-guard/releases/download/v1.4.0-rc.2/ClaudeVPNGuard_Installer.exe)**. Approve the administrator prompt.
3. Start Claude through **Claude (VPN Guard)**. Close Claude to end the monitored session.

Firewall setup must succeed before installation proceeds. Failed setup retains the previous rules and reports an error.

### Portable

1. Download the **[preview ZIP](https://github.com/gruskry/claude-vpn-guard/releases/download/v1.4.0-rc.2/claude-vpn-guard-windows.zip)** and extract the entire archive to a trusted folder.
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

The tray's **Check firewall status** command shows the selected VPN, executable paths and blocked interfaces. If launch fails, the tray remains available for repair, privacy audit and another launch attempt. Close Claude before repair or cleanup.

## Claude updates

Guard rediscovers Claude before every guarded launch. Network-address changes and executable-file events trigger verification; a periodic check runs one second after the previous full check finishes. It covers:

- The installed Claude MSIX package.
- Known Claude folders under `%LOCALAPPDATA%` and `%APPDATA%`.
- Native CLI installation paths and `claude.exe` on PATH.

For a custom installation, set `desktop_path` to the exact local `Claude.exe`. Its folder's executables are included. Relative paths, network shares and links/junctions are rejected. Update the setting if that custom executable itself moves.

**After an update changes a discovered path, or an adapter is added or renamed:**

1. Close Claude.
2. Start Guard and approve the rule-refresh prompt. Set `auto_refresh` to `false` to require manual `setup-firewall.cmd` instead.
3. Relaunch Claude through Guard.

If coverage changes during a session, Guard attempts to stop identified Claude processes before repair. Relaunch after the stopped session. File notifications reduce detection delay; they do not eliminate the first-packet race for an unknown executable.

**Changing VPN:** refreshes retain the saved tunnel. Connect the new VPN, close Claude, then run:

```powershell
powershell.exe -NoProfile -File .\setup-firewall.ps1 -ReselectVpn
```

If a driver is unrecognized, an explicit `-VpnGuid` selection is available. Inspect your VPN client and the adapter GUID before using it. Guard does not silently switch trust to another virtual network.

### Upgrading Guard

Close Claude and the previous Guard session, connect the VPN, then install **v1.4.0-rc.2** or replace the complete portable package. Installed settings are preserved. Version 1 firewall state is migrated after effective version 2 rules have been verified.

Version **1.3.2** fixes the `Desktop launch does not accept CLI arguments` error on a normal Desktop launch. If you see it in v1.3.1, update the complete package.

## Settings

Edit [`config.json`](config.json) in the Guard folder:

```json
{
  "target_timezone": "Georgian Standard Time",
  "auto_detect": true,
  "change_timezone": true,
  "auto_refresh": true,
  "disable_cli_telemetry": true,
  "clean_diagnostics_before_launch": true,
  "diagnostic_log": true,
  "desktop_path": ""
}
```

| Setting | Effect |
| --- | --- |
| `change_timezone` | Set to `false` to leave the Windows timezone unchanged. |
| `auto_detect` | When `true`, maps a recognized IANA timezone from the location check to a Windows timezone. |
| `target_timezone` | Windows timezone used when `auto_detect` is `false`. |
| `auto_refresh` | Allows one administrative repair attempt for changed or missing coverage. Disabled firewall/profile policy is not enabled automatically. |
| `disable_cli_telemetry` | Passes `DISABLE_TELEMETRY=1` and `DISABLE_ERROR_REPORTING=1` to the launched native CLI only. It can make Remote Control unavailable; set to `false` if required. These are [documented Claude Code controls](https://code.claude.com/docs/en/data-usage#telemetry-services). |
| `clean_diagnostics_before_launch` | Cleans known Sentry scope metadata before launch while Claude is closed. Set to `false` to use manual audit/cleanup. |
| `diagnostic_log` | Saves timestamps, fixed event codes and counts, with 64 KiB rotation. No raw IP, country, prompts, CLI arguments or exception text is logged. |
| `desktop_path` | Optional exact local Desktop executable; leave empty for standard discovery. |

The PowerShell launcher also accepts `-NoTimezoneChange`. Guard preserves Claude's application storage and authentication data.

> Timezone changes affect the whole Windows system and require Windows permission. Errors block launch. The original value is saved before the change and restored when the session ends. After a forced termination, recovery runs on the next guarded launch. A later manual timezone change is preserved.

## Local diagnostic privacy

Use the tray's audit/cleanup commands or:

```powershell
powershell.exe -NoProfile -File .\guard-privacy.ps1
powershell.exe -NoProfile -File .\guard-privacy.ps1 -Clean
```

Audit is read-only. Cleanup is limited to `scope_v3.json` in known Claude Sentry stores: `scope/event.user.ip_address`, culture timezone, and known geo city/country/region/coordinate fields. It preserves authentication, conversations, free-form content, other settings, log files and queued events. Claude must be closed.

Before each atomic replacement, Guard saves an encrypted backup under `%LOCALAPPDATA%\ClaudeVPNGuard\privacy-backups`. Restore a selected `.bin` with `guard-privacy.ps1 -RestoreBackup "C:\full\path\backup.bin"`. Restoration uses the same Windows account and refuses to overwrite diagnostics changed since cleanup.

Cleanup cannot erase data already sent to a server or prevent Claude from generating fresh diagnostic metadata. Support for additional queue/log schemas is pending confirmation of their format.

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
| **Coverage check fails after a Claude update** | Close Claude and relaunch Guard; approve automatic refresh, or use the tray repair command. |
| **An adapter was added or renamed** | Automatic refresh updates current matching rules after Claude is closed. |
| **No active VPN / saved VPN route changed** | Connect the saved full-tunnel VPN; explicitly reselect it if you changed VPN providers/adapters. |
| **Proxy or PAC is configured** | Use a full-tunnel VPN adapter and remove the detected proxy setting. Local relay isolation is not guaranteed. |
| **Location check times out** | Launch remains blocked. Check VPN routing and service availability; no direct unbound fallback is used. |
| **Privacy cleanup fails** | Keep the backup and original diagnostic file. Close Claude, inspect the audit result, or disable automatic cleanup until its format is understood. |
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
| Encrypted privacy backups | `%LOCALAPPDATA%\ClaudeVPNGuard\privacy-backups` |
| Bounded diagnostic events | `%LOCALAPPDATA%\ClaudeVPNGuard\guard-events.jsonl` |

Preserve these files while resolving setup or restoration errors.

</details>

## Remove

Close Claude, then uninstall through Windows settings. For a portable installation, run `remove-firewall.cmd`.

Removal restores saved DNS settings before removing Guard rules. If restoration or rule removal fails, the installer retains the application and recovery files so you can resolve the error and retry. Once the rules are removed, Claude can use physical interfaces directly.

## Scope and limitations

- **Guard is not a VPN.** Detection inspects sample routes and known tunnel types. The IPv4 location request binds the tunnel's source address and checks the actual endpoint route; it is not a probe of every Claude destination or of IPv6 public egress.
- **Checks have a delay.** They cannot guarantee that no packets escape during an interface, policy, or application change. Package rules supplement executable rules; future updates still require coverage verification.
- **Rules cover discovered native executables on enumerated interfaces.** Local relay services, WSL/Cowork/VM networking, browsers, and external tools or child executables outside the discovered installation need separate protection. Windows DNS-service traffic is not attributed to Claude by these executable rules; hostname resolution for the location request also uses Windows DNS.
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

The build rebuilds all three artifacts and compares archived file hashes with the current files. Default artifacts are unsigned. Optional signing accepts `-CertificateThumbprint` and `-SignToolPath` for an installed code-signing certificate/private key and the Windows SDK tool; it signs the launcher, installer and uninstaller and verifies launcher/installer signatures. Actual certificate-based signing remains to be exercised.

The [Windows workflow](.github/workflows/windows.yml) runs regressions, builds the installer/ZIP and uploads checksums. Tag runs prepare a release draft. The isolated suites do not run `tests/live-policy.ps1`.

`tests/live-policy.ps1` is an administrator-only smoke test using temporary rules for a temporary probe executable. Its optional `-CheckBoundLocation` makes a third-party IP lookup through the selected VPN. Traffic loss/reconnect, IPv6, DNS and install/remove acceptance still require a controlled live test setup.

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
