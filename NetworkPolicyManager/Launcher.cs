using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
        string scriptPath = Path.Combine(baseDirectory, "NetworkPolicyManager", "本地网络策略管理器.ps1");
        if (!File.Exists(scriptPath))
        {
            MessageBox.Show("找不到程序脚本：\n" + scriptPath, "本地网络策略管理器",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe"),
            Arguments = "-NoProfile -ExecutionPolicy Bypass -STA -File \"" + scriptPath + "\"",
            WorkingDirectory = baseDirectory,
            UseShellExecute = false,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        };

        try
        {
            using (Process process = Process.Start(startInfo))
            {
                string errorOutput = process.StandardError.ReadToEnd().Trim();
                process.WaitForExit();
                if (process.ExitCode != 0)
                {
                    if (errorOutput.Length > 1800)
                    {
                        errorOutput = errorOutput.Substring(0, 1800) + "…";
                    }
                    string message = "程序异常退出，退出码：" + process.ExitCode;
                    if (errorOutput.Length > 0)
                    {
                        message += "\n\n" + errorOutput;
                    }
                    MessageBox.Show(message,
                        "本地网络策略管理器", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
        catch (Exception exception)
        {
            MessageBox.Show(exception.Message, "本地网络策略管理器",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
