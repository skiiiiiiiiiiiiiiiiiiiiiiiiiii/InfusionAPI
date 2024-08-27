using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace InfusionAPI
{
        public enum InjectionStatus
        {
            FAILED,
            FAILED_ADMINISTRATOR_ACCESS,
            ALREADY_INJECTING,
            ALREADY_INJECTED,
            SUCCESS,
            OUTDATED,
        }
    }
