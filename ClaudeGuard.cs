using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Web.Script.Serialization;
using System.Collections.Generic;

[assembly: System.Reflection.AssemblyVersion("1.3.1.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.3.1.0")]

namespace ClaudeGuard
{
    // All launch decisions live in the same tested runtime used by the terminal launcher.
    static class Program
    {
        static NotifyIcon tray;
        static Form dispatcher;
        static Process supervisor;
        static volatile bool completed;
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
                menu.MenuItems.Add("Check firewall status", (s, e) => CheckStatus());
                menu.MenuItems.Add("Exit after Claude closes", (s, e) =>
                    MessageBox.Show("Close Claude to end this session and restore the timezone. Monitoring stays active until then.", "Claude Guard"));
                tray.ContextMenu = menu;
                var worker = new Thread(RunSession);
                worker.IsBackground = true;
                worker.Start();
                Application.Run();
                tray.Visible = false;
            }
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
            try
            {
                using (supervisor = new Process())
                {
                    supervisor.StartInfo = Script("sync-guard.ps1", "-LaunchClaude");
                    supervisor.OutputDataReceived += (s, e) => {};
                    supervisor.ErrorDataReceived += (s, e) => { if (e.Data != null && error.Length < 16000) lock (error) error.AppendLine(e.Data); };
                    if (!supervisor.Start()) throw new InvalidOperationException("Guard runtime could not start.");
                    supervisor.BeginOutputReadLine();
                    supervisor.BeginErrorReadLine();
                    dispatcher.BeginInvoke((Action)(() => tray.Text = "Claude Guard: session monitor"));
                    supervisor.WaitForExit();
                    if (supervisor.ExitCode != 0) throw new InvalidOperationException(error.Length == 0 ? "Launch or restoration failed. Run launch-guarded.cmd to see details." : error.ToString());
                }
            }
            catch (Exception ex)
            {
                dispatcher.Invoke((Action)(() => MessageBox.Show(ex.Message, "Claude Guard: session failed", MessageBoxButtons.OK, MessageBoxIcon.Error)));
            }
            finally
            {
                dispatcher.BeginInvoke((Action)(() => { completed = true; Application.ExitThread(); }));
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
