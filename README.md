# 🛡️ Claude VPN Guard (Windows)

![Claude VPN Guard Banner](assets/banner.jpg)

> **Zero-Leak Protection & Auto-KillSwitch for Claude Desktop & Claude Code CLI**  
> Protects your Anthropic account from accidental bans caused by VPN drops, split-tunneling leaks, and timezone/IP mismatches.

---

## ⚡ The Problem: Why Claude Accounts Get Flagged

Even if you pay with a legitimate foreign card and use a VPN, accounts frequently get flagged or blocked due to three silent Windows leaks:

1. **Split-Tunneling Leaks (Subprocess bypass):**  
   Claude Desktop and Claude Code CLI run multiple background processes (`cowork-svc.exe`, `claude.exe`, update checkers, npm wrappers). Most consumer VPNs fail to capture all child processes, silently leaking your real home IP (Beltelecom, Rostelecom, etc.) directly to Google Cloud / Anthropic edge servers.
2. **VPN Crash / Reconnect Leak:**  
   If your VPN drops for even 2 seconds, Windows immediately re-routes active TCP sockets through your physical home cable or Wi-Fi.
3. **Telemetry & Timezone Fingerprinting:**  
   Claude logs crash telemetry (Sentry) and Chromium network states (`Network Persistent State`, `Trust Tokens`). If your VPN IP is in Georgia or Germany, but your Windows timezone is set to Minsk or Moscow, this geographical mismatch is recorded.

---

## 💡 How Claude VPN Guard Solves This

Claude VPN Guard implements **3 layers of defense** directly in the Windows kernel and network stack:

```
+-------------------------------------------------------------------------+
|                              Claude Process                             |
|          (claude.exe / cowork-svc.exe / claude-code / npm CLI)          |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|           Layer 1: Windows Defender Firewall (Kernel-Level WFP)         |
+-------------------------------------------------------------------------+
   |                                                                  |
   | [BLOCKED] Physical LAN / Wi-Fi                                   | [ALLOWED] Virtual Adapters
   v                                                                  v
+------------------------------------+             +----------------------------------+
| Physical Realtek / Intel Adapters  |             | VPN Virtual Adapter (TUN/TAP)    |
| (Home ISP Cable / Home Wi-Fi)      |             | (WireGuard, OpenVPN, Outline,    |
| -> Packets dropped in < 1ms        |             |  Amnezia, Proton, Tailscale, etc)|
+------------------------------------+             +----------------------------------+
```

* **Hardware-Level Firewall Block:** Outbound traffic for Claude binaries is forbidden on physical hardware adapters (`Ethernet`, `Wi-Fi`).
* **Works with ANY VPN:** Virtual network adapters (WireGuard, OpenVPN, Outline, Amnezia, Tailscale, Proton, Windscribe, Mullvad, etc.) are left completely open.
* **Auto Timezone & Telemetry Guard:** Automatically checks the VPN endpoint IP before launch, synchronizes Windows timezone to match the server country, wipes stale telemetry caches, and restores the clock upon closing.

---

## 🚀 Quick Start (Installation in 1 Minute)

### Option 1: Automatic Installation (Recommended)
1. Download **`ClaudeVPNGuard_Installer.exe`** from [Releases](https://github.com/gruskry/claude-vpn-guard/releases/latest).
2. Run the installer (it will request Administrator privileges).
3. The installer automatically:
   - Configures Windows Defender Firewall rules for all physical adapters.
   - Installs the background Guard app.
   - Creates a beautiful desktop shortcut.

> **That's it!** You can now launch Claude through the new desktop shortcut. Even if your VPN crashes, your home internet cannot leak to Claude.

### Option 2: Manual Installation / Portable
If you prefer not to use the installer:
1. Download `claude-vpn-guard-windows.zip` from Releases and extract it.
2. Run `setup-firewall.cmd` as Administrator to block Claude on physical adapters.
3. Use the `Claude (VPN Guard).exe` or `create-desktop-shortcut.cmd` manually.

---

### DNS Leak Protection (DoH)
To prevent your home ISP from seeing your DNS queries to Anthropic, you can enable DNS-over-HTTPS (DoH) for your physical adapters. 
*(Note: If you use the `.zip` manual install, run `enable-dns-leak-protection.cmd` as Administrator).*

---

## 🎮 How to Use

### 1. Everyday Launch (The Launcher)
Always start Claude using the **`Claude (VPN Guard)`** desktop shortcut. 
* **Zero Console Windows:** Runs natively as a lightweight background app in your system tray.
* **Pre-Flight VPN Check:** Blocks launch if you forgot to turn on your VPN.
* **Auto Timezone Sync:** Matches and sets your Windows timezone to the VPN server location.
* **Telemetry Scrubbing:** Purges Sentry telemetry and Chromium persistent state caches before start.
* **Real-time Notifications:** Displays a Windows toast notification if the firewall blocks an IP leak attempt.
* **Clean Restore:** Automatically restores your original system timezone when you close Claude!

### 2. Browser Authentication (Logging In)
When you log into Claude via their website, the browser will prompt you to open the `claude://` link. 
* This will launch the original Claude app directly, bypassing the Guard launcher.
* **Is this safe? Yes.** The kernel firewall rules are permanently active. If your VPN is off, the login will safely fail without leaking your real IP.
* **Best Practice:** Always launch `Claude (VPN Guard)` from your desktop *before* clicking "Open in App" in the browser. This ensures your timezone is synced and telemetry is wiped *before* the app receives the authentication token.

### 3. Customizing Settings (`config.json`)
You can place a `config.json` file next to the `.exe` to override automatic behavior:
```json
{
    "target_timezone": "Georgian Standard Time",
    "auto_detect": true,
    "notify_on_block": true
}
```

### 4. Using Claude Code CLI
If you use the terminal CLI (`claude`):
```cmd
launch-cli-guarded.cmd
```
Or simply run `claude` in your regular terminal! The Windows Firewall rules created by the installer **permanently protect the CLI binaries** (and are immune to auto-updates via App Package rules) from leaking outside the VPN.

---

## 🔄 Compatibility Matrix

| VPN / Network Type | Supported? | Notes |
| :--- | :---: | :--- |
| **WireGuard / Amnezia / Outline** | ✅ Yes | Uses Wintun/TUN adapters, 100% compatible |
| **OpenVPN / Proton / Windscribe / Mullvad** | ✅ Yes | Uses TAP-Windows or Wintun |
| **Tailscale / ZeroTier** | ✅ Yes | Virtual overlay adapters |
| **Claude Desktop (Windows Store / MSIX)** | ✅ Yes | Auto-detected in `C:\Program Files\WindowsApps` |
| **Claude Desktop (Standalone Installer)** | ✅ Yes | Auto-detected in `%LOCALAPPDATA%` |
| **Claude Code CLI (npm / standalone)** | ✅ Yes | Auto-detected in `%APPDATA%\Claude\claude-code` |

---

## 🗑️ How to Uninstall
* **If you used the Installer:** Go to Windows Settings -> Apps -> Installed Apps (or Control Panel), find **Claude VPN Guard**, and click Uninstall. This cleanly removes all files and firewall rules automatically.
* **If you installed manually:** Run `remove-firewall.cmd` as Administrator, then delete the folder.

---

## 🛡️ Operational Security (OpSec) Tips
* **Cards & Billing:** Always align your VPN exit country with the issuing country of your payment card (e.g. Georgian card $\rightarrow$ Georgia VPN, Turkish card $\rightarrow$ Turkey VPN).
* **Additional Clock:** In Windows, enable `Settings -> Time & Language -> Date & Time -> Additional Clocks` to keep your local home time visible in the taskbar even while the primary clock is synced with the VPN.
* **Zero Browser Confusion:** Do not log into the same Claude account through an unshielded regular browser with your home IP.

---

## 📄 License
MIT License. Free for personal and commercial use.
