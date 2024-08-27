using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace InfusionAPI
{
    public class Environment
    {
        internal static string CurrentDirectory = System.Environment.CurrentDirectory;
        internal static string CeleryDirectory = Path.GetTempPath() + "\\celery";

        internal static void CreateFiles()
        {
            if (!Directory.Exists(Environment.CurrentDirectory + "\\autoexec"))
                Directory.CreateDirectory(Environment.CurrentDirectory + "\\autoexec");
            if (!Directory.Exists(Environment.CeleryDirectory))
                Directory.CreateDirectory(Environment.CeleryDirectory);
            File.WriteAllText(Environment.CeleryDirectory + "\\celeryhome.txt", Environment.CurrentDirectory);
            File.WriteAllText(Environment.CeleryDirectory + "\\robloxexe.txt", "");
            File.WriteAllText(Environment.CeleryDirectory + "\\autolaunch.txt", "");
            File.WriteAllText(Environment.CeleryDirectory + "\\callback.txt", "");
            File.WriteAllText(Environment.CeleryDirectory + "\\CeleryLog.txt", "");
            File.WriteAllText(Environment.CeleryDirectory + "\\robloxexe.txt", "");
            File.WriteAllText(Environment.CeleryDirectory + "\\launchargs.txt", "");
            if (!Directory.Exists(Environment.CeleryDirectory + "\\workspace"))
                Directory.CreateDirectory(Environment.CeleryDirectory + "\\workspace");
            if (!Directory.Exists(Environment.CurrentDirectory + "\\autoexec"))
                Directory.CreateDirectory(Environment.CurrentDirectory + "\\autoexec");
            if (!File.Exists(Environment.CurrentDirectory + "\\autoexec\\autoexec.lua"))
                File.WriteAllText(Environment.CurrentDirectory + "\\autoexec\\autoexec.lua", "");
            if (Directory.Exists(Environment.CurrentDirectory + "\\bin"))
                return;
            Directory.CreateDirectory("bin");
        }
    }
}