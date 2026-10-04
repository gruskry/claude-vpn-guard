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

## 🚀 Quick Start (Installation in 2 Minutes)

### Step 1: Download
* **Option 1 (Easiest):** Download the latest **`claude-vpn-guard-windows.zip`** from [Releases](https://github.com/gruskry/claude-vpn-guard/releases/latest) and extract it anywhere (e.g. `C:\claude-vpn-guard` or `E:\claude-tools`).
* **Option 2 (Git):**
  ```bash
  git clone https://github.com/gruskry/claude-vpn-guard.git
  cd claude-vpn-guard
  ```

### Step 2: Activate Kernel Firewall Protection (1 Click)
1. Right-click **`setup-firewall.cmd`** and select **Run as Administrator** (or double-click and accept UAC).
2. The script will automatically:
   - Detect your physical network cards (Ethernet / Wi-Fi).
   - Scan your system for all Claude Desktop and Claude Code CLI executables.
   - Register outbound block rules in Windows Defender Firewall.
3. You will see a green confirmation: `SUCCESS! Created X firewall rule(s)`.

> **That's it!** Even if your VPN crashes, your home internet cannot leak to Claude.

### Step 3: (Optional) Create Desktop Shortcut
Double-click **`create-desktop-shortcut.cmd`** to place a beautiful launch shortcut with the official Claude icon right onto your Windows Desktop.

---

### Option B: DNS Leak Protection (DoH)
Included is a script to enable DNS-over-HTTPS (DoH) globally for physical network adapters, preventing your home ISP from seeing your DNS queries to Anthropic.
1. Run **`enable-dns-leak-protection.cmd`** as Administrator.
2. It secures `1.1.1.1` and `8.8.8.8` DNS queries via DoH.

---

## 🎮 How to Use

### Using the `Claude (VPN Guard)` Launcher
Double-click the **`Claude (VPN Guard)`** desktop shortcut (or **`Claude (VPN Guard).exe`**):
* **Zero Console Windows:** Runs natively as a lightweight background app with a system tray icon.
* **Pre-Flight VPN Check:** Blocks launch if you forgot to turn on your VPN or if your real home IP is exposed.
* **Auto Timezone Sync:** Matches and sets your Windows timezone to the VPN server location.
* **Telemetry Scrubbing:** Purges Sentry telemetry and Chromium persistent state caches before start.
* **Real-time Notifications:** Displays a native Windows notification if the firewall blocks an IP leak attempt.
* **Clean Restore:** Automatically restores your original system timezone when Claude closes!

### Customizing Settings (`config.json`)
You can place a `config.json` file next to the `.exe` to override automatic behavior:
```json
{
    "target_timezone": "Georgian Standard Time",
    "auto_detect": true,
    "notify_on_block": true
}
```

### Option C: Using Claude Code CLI
If you use the terminal CLI (`claude`):
```cmd
launch-cli-guarded.cmd
```
Or simply run `claude` in your regular terminal! The Windows Firewall rules created in Step 2 **permanently protect the CLI binaries** (and are immune to auto-updates via App Package rules) from leaking outside the VPN.

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
If you ever want to remove all firewall rules:
* Double-click **`remove-firewall.cmd`** (Run as Administrator).
* All rules prefixed with `Claude-VPN-Guard-Block` will be deleted instantly.

---

## 🛡️ Operational Security (OpSec) Tips
* **Cards & Billing:** Always align your VPN exit country with the issuing country of your payment card (e.g. Georgian card $\rightarrow$ Georgia VPN, Turkish card $\rightarrow$ Turkey VPN).
* **Additional Clock:** In Windows, enable `Settings -> Time & Language -> Date & Time -> Additional Clocks` to keep your local home time visible in the taskbar even while the primary clock is synced with the VPN.
* **Zero Browser Confusion:** Do not log into the same Claude account through an unshielded regular browser with your home IP.

---

## 📄 License
MIT License. Free for personal and commercial use.
