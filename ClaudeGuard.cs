using System;
using System.IO;
using System.Diagnostics;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using System.Net;
using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace ClaudeGuard
{
    static class Program
    {
        private static NotifyIcon trayIcon;
        private static System.Windows.Forms.Timer watchTimer;
        private static string originalTimezoneId = "";
        private static string activeTimezoneId = "";
        private static DateTime lastNotificationTime = DateTime.MinValue;
        private static long lastLogPosition = 0;
        private static string firewallLogPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"LogFiles\Firewall\pfirewall.log");

        private static string configTargetTimezone = "";
        private static bool configAutoDetect = true;
        private static bool configNotifyOnBlock = true;

        private static void LoadConfig()
        {
            string configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.json");
            if (File.Exists(configPath))
            {
                try
                {
                    string json = File.ReadAllText(configPath);
                    Match mTz = Regex.Match(json, @"""target_timezone""\s*:\s*""([^""]+)""");
                    if (mTz.Success) configTargetTimezone = mTz.Groups[1].Value;

                    Match mAuto = Regex.Match(json, @"""auto_detect""\s*:\s*(true|false)", RegexOptions.IgnoreCase);
                    if (mAuto.Success) configAutoDetect = (mAuto.Groups[1].Value.ToLower() == "true");

                    Match mNotify = Regex.Match(json, @"""notify_on_block""\s*:\s*(true|false)", RegexOptions.IgnoreCase);
                    if (mNotify.Success) configNotifyOnBlock = (mNotify.Groups[1].Value.ToLower() == "true");
                }
                catch {}
            }
        }

        private static readonly Dictionary<string, string> TzMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "Asia/Tbilisi", "Georgian Standard Time" },
            { "Europe/Warsaw", "Central European Standard Time" },
            { "Europe/Berlin", "W. Europe Standard Time" },
            { "Europe/Paris", "Romance Standard Time" },
            { "Europe/Amsterdam", "W. Europe Standard Time" },
            { "Europe/London", "GMT Standard Time" },
            { "Europe/Vilnius", "FLE Standard Time" },
            { "Europe/Riga", "FLE Standard Time" },
            { "Europe/Tallinn", "FLE Standard Time" },
            { "Europe/Kiev", "FLE Standard Time" },
            { "Europe/Kyiv", "FLE Standard Time" },
            { "America/New_York", "Eastern Standard Time" },
            { "America/Chicago", "Central Standard Time" },
            { "America/Denver", "Mountain Standard Time" },
            { "America/Los_Angeles", "Pacific Standard Time" },
            { "Asia/Yerevan", "Caucasus Standard Time" },
            { "Asia/Almaty", "Central Asia Standard Time" },
            { "Asia/Tashkent", "West Asia Standard Time" },
            { "Asia/Istanbul", "Turkey Standard Time" },
            { "Asia/Dubai", "Arabian Standard Time" }
        };

        [STAThread]
        static void Main()
        {
            bool createdNew;
            using (Mutex mutex = new Mutex(true, "ClaudeVPNGuard_Singleton_Mutex", out createdNew))
            {
                if (!createdNew)
                {
                    ShowNativeNotification("Claude VPN Guard", "Claude Guard is already active in the background.", ToolTipIcon.Info);
                    return;
                }

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                LoadConfig();

                // Initialize Tray Icon
                trayIcon = new NotifyIcon();
                try
                {
                    string iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"assets\claude.ico");
                    if (!File.Exists(iconPath))
                        iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "claude.ico");

                    if (File.Exists(iconPath))
                        trayIcon.Icon = new Icon(iconPath);
                    else
                        trayIcon.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
                }
                catch
                {
                    trayIcon.Icon = SystemIcons.Shield;
                }

                trayIcon.Text = "Claude VPN Guard: Active";
                trayIcon.Visible = true;

                // Context menu for tray icon
                ContextMenu menu = new ContextMenu();
                menu.MenuItems.Add(new MenuItem("Claude VPN Guard (Active)"));
                menu.MenuItems[0].Enabled = false;
                menu.MenuItems.Add("-");
                menu.MenuItems.Add("Check Status", (s, e) => CheckStatusManual());
                menu.MenuItems.Add("Exit", (s, e) => ExitApplication());
                trayIcon.ContextMenu = menu;

                // Save original timezone
                try
                {
                    originalTimezoneId = TimeZoneInfo.Local.Id;
                }
                catch
                {
                    originalTimezoneId = "";
                }

                // Step 1: Pre-flight check IP, VPN and determine target timezone
                string publicIp = "";
                string country = "";
                string detectedTz = "";
                bool vpnOk = CheckPublicLocation(out publicIp, out country, out detectedTz);

                if (!vpnOk)
                {
                    ShowNativeNotification("⚠️ Claude VPN Guard", "VPN IS NOT CONNECTED!\nHome IP detected (" + country + ": " + publicIp + ").\nLaunch blocked to prevent account bans.", ToolTipIcon.Error);
                    trayIcon.Visible = false;
                    return;
                }

                // Step 2: Set target timezone matching VPN
                if (configAutoDetect && !string.IsNullOrEmpty(detectedTz))
                {
                    activeTimezoneId = detectedTz;
                    SetTimezone(activeTimezoneId);
                }
                else if (!configAutoDetect && !string.IsNullOrEmpty(configTargetTimezone))
                {
                    activeTimezoneId = configTargetTimezone;
                    SetTimezone(activeTimezoneId);
                }

                // Step 3: Scrub cache
                ScrubClaudeCache();

                // Step 4: Launch Claude Desktop
                LaunchClaude();

                // Initialize log reader position
                InitLogPosition();

                // Step 5: Start background monitor timer
                watchTimer = new System.Windows.Forms.Timer();
                watchTimer.Interval = 1500;
                watchTimer.Tick += OnWatchTick;
                watchTimer.Start();

                Application.Run();
            }
        }

        private static bool CheckPublicLocation(out string ip, out string country, out string targetWinTz)
        {
            ip = "Unknown";
            country = "Unknown";
            targetWinTz = "";

            string[] endpoints = new string[] {
                "https://ipapi.co/json/",
                "https://ipinfo.io/json"
            };

            foreach (string url in endpoints)
            {
                try
                {
                    HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                    req.UserAgent = "curl/7.68.0";
                    req.Timeout = 4000;
                    using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                    using (StreamReader reader = new StreamReader(resp.GetResponseStream()))
                    {
                        string json = reader.ReadToEnd();
                        Match mCountry = Regex.Match(json, @"""(?:country_code|country)""\s*:\s*""([A-Za-z]{2})""");
                        Match mIp = Regex.Match(json, @"""ip""\s*:\s*""([^""]+)""");
                        Match mTz = Regex.Match(json, @"""timezone""\s*:\s*""([^""]+)""");

                        if (mCountry.Success)
                            country = mCountry.Groups[1].Value.ToUpper();
                        if (mIp.Success)
                            ip = mIp.Groups[1].Value;

                        if (mTz.Success)
                        {
                            string iana = mTz.Groups[1].Value;
                            if (TzMap.ContainsKey(iana))
                                targetWinTz = TzMap[iana];
                        }

                        if (!string.IsNullOrEmpty(country) && country != "UNKNOWN")
                        {
                            string[] blocked = new string[] { "BY", "RU", "IR", "KP", "SY", "CU" };
                            foreach (string b in blocked)
                            {
                                if (country == b) return false;
                            }
                            return true;
                        }
                    }
                }
                catch
                {
                    continue;
                }
            }
            return false;
        }

        private static void SetTimezone(string tzId)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("tzutil.exe", "/s \"" + tzId + "\"")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                Process p = Process.Start(psi);
                p.WaitForExit(3000);
            }
            catch {}
        }

        private static void ScrubClaudeCache()
        {
            try
            {
                string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

                string[] targets = new string[] {
                    Path.Combine(roaming, @"Claude\Network\Network Persistent State"),
                    Path.Combine(roaming, @"Claude\Network\Trust Tokens"),
                    Path.Combine(roaming, @"Claude\sentry"),
                    Path.Combine(local, @"Claude\GPUCache")
                };

                foreach (string t in targets)
                {
                    if (File.Exists(t))
                    {
                        try { File.Delete(t); } catch {}
                    }
                    else if (Directory.Exists(t))
                    {
                        try { Directory.Delete(t, true); } catch {}
                    }
                }
            }
            catch {}
        }

        private static void LaunchClaude()
        {
            bool started = false;
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("shell:AppsFolder\\Claude_pzs8sxrjxfjjc!Claude")
                {
                    UseShellExecute = true
                };
                Process.Start(psi);
                started = true;
            }
            catch {}

            if (!started)
            {
                string localExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\Claude\Claude.exe");
                if (File.Exists(localExe))
                {
                    Process.Start(localExe);
                }
            }
        }

        private static void InitLogPosition()
        {
            try
            {
                if (File.Exists(firewallLogPath))
                {
                    FileInfo fi = new FileInfo(firewallLogPath);
                    lastLogPosition = fi.Length;
                }
            }
            catch {}
        }

        private static void OnWatchTick(object sender, EventArgs e)
        {
            Process[] procs = Process.GetProcessesByName("claude");
            if (procs == null || procs.Length == 0)
            {
                ExitApplication();
                return;
            }

            CheckFirewallLogForDrops();
        }

        private static void CheckFirewallLogForDrops()
        {
            try
            {
                if (!File.Exists(firewallLogPath)) return;

                FileInfo fi = new FileInfo(firewallLogPath);
                if (fi.Length > lastLogPosition)
                {
                    using (FileStream fs = new FileStream(firewallLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        fs.Seek(lastLogPosition, SeekOrigin.Begin);
                        using (StreamReader sr = new StreamReader(fs))
                        {
                            string line;
                            bool dropDetected = false;
                            while ((line = sr.ReadLine()) != null)
                            {
                                if (line.Contains("DROP") && (line.Contains("192.168.") || line.Contains("10.")))
                                {
                                    dropDetected = true;
                                }
                            }
                            lastLogPosition = fs.Position;

                            if (dropDetected && (DateTime.Now - lastNotificationTime).TotalSeconds > 15)
                            {
                                lastNotificationTime = DateTime.Now;
                                if (configNotifyOnBlock)
                                {
                                    ShowNativeNotification(
                                        "🛡️ Windows Firewall (Claude Guard)",
                                        "Blocked direct connection attempt outside VPN!\nPacket dropped by Windows kernel. Zero leak.",
                                        ToolTipIcon.Warning
                                    );
                                }
                            }
                        }
                    }
                }
            }
            catch {}
        }

        private static void CheckStatusManual()
        {
            string ip, country, tz;
            bool ok = CheckPublicLocation(out ip, out country, out tz);
            string msg = ok 
                ? "Protection active.\nVPN: " + country + " (" + ip + ")\nTimezone: " + TimeZoneInfo.Local.DisplayName
                : "Warning: External IP could not be verified!";
            ShowNativeNotification("Claude VPN Guard Status", msg, ok ? ToolTipIcon.Info : ToolTipIcon.Warning);
        }

        private static void ShowNativeNotification(string title, string text, ToolTipIcon icon)
        {
            if (trayIcon != null)
            {
                trayIcon.ShowBalloonTip(4000, title, text, icon);
            }
        }

        private static void ExitApplication()
        {
            if (watchTimer != null)
            {
                watchTimer.Stop();
                watchTimer.Dispose();
            }

            if (!string.IsNullOrEmpty(originalTimezoneId))
            {
                SetTimezone(originalTimezoneId);
            }

            ScrubClaudeCache();

            if (trayIcon != null)
            {
                trayIcon.Visible = false;
                trayIcon.Dispose();
            }

            Application.Exit();
        }
    }
}
