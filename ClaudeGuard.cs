using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Web.Script.Serialization;
using System.Collections.Generic;

[assembly: System.Reflection.AssemblyVersion("1.4.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.4.0.0")]

namespace ClaudeGuard
{
    // All launch decisions live in the same tested runtime used by the terminal launcher.
    static class Program
    {
        static NotifyIcon tray;
        static Form dispatcher;
        static Process supervisor;
        static Form launchWindow;
        static Label launchStage;
        static volatile bool completed;
        static volatile bool sessionRunning;
        static volatile bool maintenanceRunning;
        static readonly string BaseDirectory = AppDomain.CurrentDomain.BaseDirectory;

        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            using (dispatcher = new Form())
            using (tray = new NotifyIcon())
            {
                // Force creation of a UI-thread handle before background callbacks.
                IntPtr handle = dispatcher.Handle;
                tray.Icon = SystemIcons.Shield;
                string icon = Path.Combine(BaseDirectory, @"assets\claude.ico");
                if (File.Exists(icon)) { try { tray.Icon = new Icon(icon); } catch {} }
                tray.Text = "Claude Guard: checking launch";
                tray.Visible = true;
                var menu = new ContextMenu();
                menu.MenuItems.Add("Start guarded Claude", (s, e) => BeginSession());
                menu.MenuItems.Add("Check firewall status", (s, e) => CheckStatus());
                menu.MenuItems.Add("Repair firewall rules", (s, e) => RunMaintenance("setup-firewall.ps1", "-NonInteractive"));
                menu.MenuItems.Add("Audit local diagnostic metadata", (s, e) => RunMaintenance("guard-privacy.ps1", ""));
                menu.MenuItems.Add("Clean local diagnostic metadata", (s, e) => RunMaintenance("guard-privacy.ps1", "-Clean"));
                menu.MenuItems.Add("Restore diagnostic backup", (s, e) => {
                    if (sessionRunning || maintenanceRunning) { MessageBox.Show("Close Claude and finish maintenance before restoring a backup.", "Claude Guard"); return; }
                    using (var dialog = new OpenFileDialog()) {
                        dialog.Title = "Select an encrypted diagnostic backup";
                        dialog.InitialDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"ClaudeVPNGuard\privacy-backups");
                        dialog.Filter = "Encrypted backup (*.bin)|*.bin";
                        if (dialog.ShowDialog() == DialogResult.OK) RunMaintenance("guard-privacy.ps1", "-RestoreBackup \"" + dialog.FileName + "\"");
                    }
                });
                menu.MenuItems.Add("Exit", (s, e) => {
                    if (sessionRunning || maintenanceRunning) MessageBox.Show("Close Claude and finish the current maintenance operation before exiting.", "Claude Guard");
                    else { completed = true; Application.ExitThread(); }
                });
                tray.ContextMenu = menu;
                BeginSession();
                Application.Run();
                tray.Visible = false;
            }
        }

        static void BeginSession()
        {
            if (sessionRunning || maintenanceRunning || completed) return;
            sessionRunning = true;
            ShowLaunchProgress();
            var worker = new Thread(RunSession);
            worker.IsBackground = true; worker.Start();
        }

        static void ShowLaunchProgress()
        {
            CloseLaunchProgress();
            launchWindow = new Form {
                Text = "Claude VPN Guard", ClientSize = new Size(460, 205),
                FormBorderStyle = FormBorderStyle.FixedDialog, ControlBox = false,
                StartPosition = FormStartPosition.CenterScreen, ShowInTaskbar = true,
                BackColor = Color.FromArgb(247, 248, 250),
                Font = new Font("Segoe UI", 10), AutoScaleMode = AutoScaleMode.Dpi
            };
            launchWindow.Controls.Add(new Label {
                Text = "Проверяем защиту перед запуском", AutoSize = false,
                Location = new Point(24, 22), Size = new Size(412, 30),
                Font = new Font("Segoe UI", 13, FontStyle.Bold)
            });
            launchStage = new Label {
                Text = "Подготовка проверки…", AutoSize = false,
                Location = new Point(24, 66), Size = new Size(412, 25)
            };
            launchWindow.Controls.Add(launchStage);
            launchWindow.Controls.Add(new ProgressBar {
                Location = new Point(24, 103), Size = new Size(412, 8),
                Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 30
            });
            launchWindow.Controls.Add(new Label {
                Text = "Пожалуйста, подождите. Claude откроется автоматически.\nПроверка может занять минуту или больше.",
                Location = new Point(24, 132), Size = new Size(412, 52),
                ForeColor = Color.FromArgb(80, 87, 98)
            });
            tray.Text = "Claude Guard: checking launch";
            launchWindow.Show();
        }

        static void CloseLaunchProgress()
        {
            if (launchWindow != null) { launchWindow.Close(); launchWindow.Dispose(); launchWindow = null; }
            launchStage = null;
        }

        static void ReceiveLaunchProgress(string line)
        {
            const string prefix = "[ClaudeGuardProgress]";
            if (line == null || !line.StartsWith(prefix, StringComparison.Ordinal)) return;
            string stage = line.Substring(prefix.Length);
            string message;
            switch (stage) {
                case "initializing": message = "Проверяем настройки запуска…"; break;
                case "discovery": message = "Находим установленный Claude…"; break;
                case "firewall": message = "Проверяем VPN и правила защиты…"; break;
                case "privacy": message = "Проверяем локальную диагностику…"; break;
                case "location": message = "Проверяем подключение через VPN…"; break;
                case "timezone": message = "Подготавливаем часовой пояс…"; break;
                case "final-check": message = "Завершаем проверку защиты…"; break;
                case "starting": message = "Запускаем Claude…"; break;
                case "started": message = null; break;
                default: return;
            }
            try {
                dispatcher.BeginInvoke((Action)(() => {
                    if (stage == "started") { CloseLaunchProgress(); tray.Text = "Claude Guard: session monitor"; }
                    else if (launchStage != null) launchStage.Text = message;
                }));
            } catch (InvalidOperationException) { /* Application has already finished. */ }
        }

        static void RunMaintenance(string script, string arguments)
        {
            if (maintenanceRunning || completed) return;
            if (sessionRunning && script != "guard-privacy.ps1") {
                MessageBox.Show("Close Claude before repairing firewall rules.", "Claude Guard"); return;
            }
            maintenanceRunning = true;
            var worker = new Thread(() => {
                string message;
                try {
                    using (var process = new Process()) {
                        process.StartInfo = Script(script, arguments);
                        var output = new StringBuilder(); var error = new StringBuilder();
                        process.OutputDataReceived += (s, e) => { if (e.Data != null && output.Length < 16000) output.AppendLine(e.Data); };
                        process.ErrorDataReceived += (s, e) => { if (e.Data != null && error.Length < 16000) error.AppendLine(e.Data); };
                        process.Start(); process.BeginOutputReadLine(); process.BeginErrorReadLine();
                        process.WaitForExit();
                        message = process.ExitCode == 0 ? output.ToString() : error.ToString();
                        if (message.Length == 0) message = process.ExitCode == 0 ? "Completed." : "Operation failed. Run the matching command in the Guard folder for details.";
                    }
                } catch (Exception ex) { message = ex.Message; }
                if (!completed) try { dispatcher.BeginInvoke((Action)(() => { maintenanceRunning = false; MessageBox.Show(message, "Claude Guard"); })); } catch (InvalidOperationException) {}
            });
            worker.IsBackground = true; worker.Start();
        }

        static ProcessStartInfo Script(string name, string arguments)
        {
            string path = Path.Combine(BaseDirectory, name);
            if (!File.Exists(path)) throw new FileNotFoundException("Guard component is missing. Reinstall the complete package.", path);
            return new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe"),
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + path + "\" " + arguments)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
            };
        }

        static void RunSession()
        {
            var error = new StringBuilder();
            string launchError = null;
            bool success = false;
            try
            {
                using (supervisor = new Process())
                {
                    supervisor.StartInfo = Script("sync-guard.ps1", "-LaunchClaude -ProgressMessages");
                    supervisor.OutputDataReceived += (s, e) => ReceiveLaunchProgress(e.Data);
                    supervisor.ErrorDataReceived += (s, e) => {
                        if (e.Data == null) return;
                        const string prefix = "[ClaudeGuardError]";
                        lock (error) {
                            if (e.Data.StartsWith(prefix, StringComparison.Ordinal)) launchError = e.Data.Substring(prefix.Length);
                            else if (error.Length < 1600) error.AppendLine(e.Data.Length > 400 ? e.Data.Substring(0, 400) + "…" : e.Data);
                        }
                    };
                    if (!supervisor.Start()) throw new InvalidOperationException("Guard runtime could not start.");
                    supervisor.BeginOutputReadLine();
                    supervisor.BeginErrorReadLine();
                    supervisor.WaitForExit();
                    if (supervisor.ExitCode != 0) {
                        string failure;
                        lock (error) failure = launchError ?? (error.Length == 0 ? "Launch or restoration failed. Run launch-guarded.cmd to see details." : error.ToString());
                        if (failure.Length > 2000) failure = failure.Substring(0, 2000) + "…";
                        throw new InvalidOperationException(failure);
                    }
                    success = true;
                }
            }
            catch (Exception ex)
            {
                dispatcher.Invoke((Action)(() => {
                    CloseLaunchProgress();
                    MessageBox.Show(ex.Message, "Claude Guard: session failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }));
            }
            finally
            {
                dispatcher.BeginInvoke((Action)(() => {
                    sessionRunning = false;
                    CloseLaunchProgress();
                    if (success) { completed = true; Application.ExitThread(); }
                    else tray.Text = "Claude Guard: launch blocked";
                }));
            }
        }

        static void CheckStatus()
        {
            if (completed) return;
            var worker = new Thread(() =>
            {
                string message;
                try
                {
                    using (var process = Process.Start(Script("check-protection.ps1", "-Json")))
                    {
                        // Drain both pipes concurrently; policy providers can produce verbose errors.
                        var output = new StringBuilder();
                        process.OutputDataReceived += (s, e) => { if (e.Data != null && output.Length < 16000) output.AppendLine(e.Data); };
                        process.ErrorDataReceived += (s, e) => {};
                        process.BeginOutputReadLine(); process.BeginErrorReadLine();
                        if (!process.WaitForExit(20000)) { process.Kill(); throw new TimeoutException("Firewall verification timed out; protection is unverified."); }
                        process.WaitForExit();
                        var data = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(output.ToString());
                        message = (process.ExitCode == 0 ? "Firewall verification passed.\n" : "Firewall verification failed.\n") + Convert.ToString(data["Message"]);
                        if (data.ContainsKey("Programs")) {
                            message += "\n\nClaude paths:\n";
                            foreach (object path in (System.Collections.IEnumerable)data["Programs"]) message += Convert.ToString(path) + "\n";
                        }
                        if (data.ContainsKey("BlockedInterfaces")) {
                            message += "\nBlocked interfaces:\n";
                            foreach (object adapter in (System.Collections.IEnumerable)data["BlockedInterfaces"]) message += Convert.ToString(adapter) + "\n";
                        }
                        if (data.ContainsKey("Limits")) message += "\n" + Convert.ToString(data["Limits"]);
                    }
                }
                catch (Exception ex) { message = ex.Message; }
                if (!completed)
                {
                    try { dispatcher.BeginInvoke((Action)(() => MessageBox.Show(message, "Claude Guard status"))); }
                    catch (InvalidOperationException) { /* Session finished while the status check was running. */ }
                }
            });
            worker.IsBackground = true;
            worker.Start();
        }
    }
}
