using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace InfusionAPI
{
    public class QuickScript
    {
        public static void Unc()
        {
            ExploitApi.Execute(new WebClient().DownloadString("https://raw.githubusercontent.com/unified-naming-convention/NamingStandard/main/UNCCheckEnv.lua"));
        }
    }
}
