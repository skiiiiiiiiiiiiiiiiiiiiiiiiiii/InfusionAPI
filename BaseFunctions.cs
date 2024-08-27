using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace InfusionAPI
{
    public class BaseFunctions
    {
        public const uint PAGE_NOACCESS = 1;
        public const uint PAGE_READONLY = 2;
        public const uint PAGE_READWRITE = 4;
        public const uint PAGE_WRITECOPY = 8;
        public const uint PAGE_EXECUTE = 16;
        public const uint PAGE_EXECUTE_READ = 32;
        public const uint PAGE_EXECUTE_READWRITE = 64;
        public const uint PAGE_EXECUTE_WRITECOPY = 128;
        public const uint PAGE_GUARD = 256;
        public const uint PAGE_NOCACHE = 512;
        public const uint PAGE_WRITECOMBINE = 1024;
        public const uint MEM_COMMIT = 4096;
        public const uint MEM_RESERVE = 8192;
        public const uint MEM_DECOMMIT = 16384;
        public const uint MEM_RELEASE = 32768;
        public const uint PROCESS_WM_READ = 16;
        public const uint PROCESS_ALL_ACCESS = 2035711;
        private const uint GENERIC_WRITE = 1073741824;
        private const uint GENERIC_READ = 2147483648;
        private const uint FILE_SHARE_READ = 1;
        private const uint FILE_SHARE_WRITE = 2;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 128;
        private const uint ERROR_ACCESS_DENIED = 5;
        private const uint ATTACH_PARENT = 4294967295;
        public const int EXCEPTION_CONTINUE_EXECUTION = -1;
        public const int EXCEPTION_CONTINUE_SEARCH = 0;
        public const uint STD_OUTPUT_HANDLE = 4294967285;
        public const int MY_CODE_PAGE = 437;
        public const int SW_HIDE = 0;
        public const int SW_SHOW = 5;
        public const long WAIT_TIMEOUT = 258;
        private static List<ulong> openedHandles = new List<ulong>();

        public static bool checkCreateFile(string path)
        {
            if (System.IO.File.Exists(path))
                return true;
            try
            {
                System.IO.File.Create(path).Close();
                return true;
            }
            catch (Exception ex)
            {
                int num = (int)MessageBox.Show("There was an issue while trying to create file `" + path + "`...Please restart and run as an administrator");
            }
            return false;
        }

        public static bool createFileText(string filepath, string content)
        {
            try
            {
                try
                {
                    System.IO.File.CreateText(filepath);
                }
                catch (Exception ex)
                {
                    int num = (int)MessageBox.Show("There was an issue while trying to create file `" + filepath + "`...Please restart and run as an administrator");
                }
                try
                {
                    System.IO.File.WriteAllText(filepath, content);
                    return true;
                }
                catch (Exception ex)
                {
                }
            }
            catch (Exception ex)
            {
            }
            return false;
        }

        public static bool checkCreateFile(string path, string defaultValue)
        {
            BaseFunctions.checkCreateFile(path);
            try
            {
                System.IO.File.WriteAllText(path, defaultValue);
                return true;
            }
            catch (Exception ex)
            {
                int num = (int)MessageBox.Show("There was an issue while trying to write to a file...Please close restart and run as an administrator");
                return false;
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(ulong hProcess, uint dwMilliseconds);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtSetInformationProcess(
          ulong hProcess,
          int processInformationClass,
          ref BaseFunctions.PROCESS_INSTRUMENTATION_CALLBACK processInformation,
          int processInformationLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtQueryInformationProcess(
          ulong processHandle,
          int processInformationClass,
          ref BaseFunctions.PROCESS_INSTRUMENTATION_CALLBACK processInformation,
          uint processInformationLength,
          ref int returnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern bool NtDuplicateHandle(
          ulong hSourceProcess,
          ulong hSourceHandle,
          ulong hTargetProcess,
          ulong lpTargetHandle,
          uint dwDesiredAccess,
          bool bInheritHandle,
          uint dwOptions);

        [DllImport("user32.dll")]
        public static extern int FindWindow(string sClass, string sWindow);

        [DllImport("user32.dll")]
        public static extern bool ShowWindow(int hWnd, int nCmdShow);

        [DllImport("user32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern int MessageBoxA(int hWnd, string sMessage, string sCaption, uint mbType);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int MessageBoxW(int hWnd, string sMessage, string sCaption, uint mbType);

        [DllImport("kernel32.dll")]
        public static extern int GetConsoleWindow();

        [DllImport("kernel32.dll")]
        public static extern ulong OpenProcess(
          uint dwDesiredAccess,
          bool bInheritHandle,
          int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(
          ulong hProcess,
          ulong lpBaseAddress,
          byte[] lpBuffer,
          int dwSize,
          ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(
          ulong hProcess,
          ulong lpBaseAddress,
          byte[] lpBuffer,
          int dwSize,
          ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(
          ulong hProcess,
          ulong lpBaseAddress,
          int dwSize,
          uint new_protect,
          ref uint lpOldProtect);

        [DllImport("kernel32.dll")]
        public static extern ulong VirtualQueryEx(
          ulong hProcess,
          ulong lpAddress,
          out BaseFunctions.MEMORY_BASIC_INFORMATION lpBuffer,
          uint dwLength);

        [DllImport("kernel32.dll")]
        public static extern ulong VirtualAllocEx(
          ulong hProcess,
          ulong lpAddress,
          int size,
          uint allocation_type,
          uint protect);

        [DllImport("kernel32.dll")]
        public static extern ulong VirtualFreeEx(
          ulong hProcess,
          ulong lpAddress,
          int size,
          uint allocation_type);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern ulong GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern ulong GetProcAddress(ulong hModule, string procName);

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(ulong hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetExitCodeProcess(ulong hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll")]
        public static extern int CreateRemoteThread(
          ulong hProcess,
          int lpThreadAttributes,
          uint dwStackSize,
          int lpStartAddress,
          int lpParameter,
          uint dwCreationFlags,
          out int lpThreadId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern uint GetStdHandle(uint nStdHandle);

        [DllImport("kernel32.dll")]
        public static extern void SetStdHandle(uint nStdHandle, uint handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern int AllocConsole();

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern bool SetConsoleTitle(string lpConsoleTitle);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern uint AttachConsole(uint dwProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern uint CreateFileW(
          string lpFileName,
          uint dwDesiredAccess,
          uint dwShareMode,
          uint lpSecurityAttributes,
          uint dwCreationDisposition,
          uint dwFlagsAndAttributes,
          uint hTemplateFile);

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentProcessId();

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint CreateFile(
          string lpFileName,
          uint dwDesiredAccess,
          uint dwShareMode,
          uint lpSecurityAttributes,
          uint dwCreationDisposition,
          uint dwFlagsAndAttributes,
          uint hTemplateFile);

        public static List<BaseFunctions.ProcInfo> openProcessesByName(string processName)
        {
            List<BaseFunctions.ProcInfo> procInfoList = new List<BaseFunctions.ProcInfo>();
            foreach (Process process in Process.GetProcessesByName(processName.Replace(".exe", "")))
            {
                try
                {
                    if (process.Id != 0 && !process.HasExited)
                        procInfoList.Add(new BaseFunctions.ProcInfo()
                        {
                            processRef = process,
                            baseModule = 0UL,
                            handle = 0UL,
                            processId = (ulong)process.Id,
                            processName = processName,
                            windowName = ""
                        });
                }
                catch (NullReferenceException ex)
                {
                }
                catch (Exception ex)
                {
                }
            }
            return procInfoList;
        }

        public void flush()
        {
            foreach (ulong openedHandle in BaseFunctions.openedHandles)
                BaseFunctions.CloseHandle(openedHandle);
        }

        public struct MEMORY_BASIC_INFORMATION
        {
            public int BaseAddress;
            public int AllocationBase;
            public uint AllocationProtect;
            public int RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public struct PROCESS_INSTRUMENTATION_CALLBACK
        {
            public uint Version;
            public uint Reserved;
            public IntPtr Callback;
        }

        public static class ConsoleHelper
        {
            public static StreamWriter writer;
            public static FileStream fwriter;

            public static Process ExecuteAsAdmin(string fileName, bool cnsl, bool admin)
            {
                Process process = new Process();
                process.StartInfo.FileName = fileName;
                process.StartInfo.UseShellExecute = true;
                process.StartInfo.Arguments = "abc123";
                if (admin)
                    process.StartInfo.Verb = "runas";
                if (!cnsl)
                {
                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                }
                process.Start();
                return process;
            }

            public static void Initialize(bool alwaysCreateNewConsole = true)
            {
                bool flag = true;
                if (alwaysCreateNewConsole || BaseFunctions.AttachConsole(uint.MaxValue) == 0U && Marshal.GetLastWin32Error() != 5)
                    flag = BaseFunctions.AllocConsole() != 0;
                if (flag)
                {
                    BaseFunctions.ConsoleHelper.InitializeOutStream();
                    BaseFunctions.ConsoleHelper.InitializeInStream();
                }
                Console.OutputEncoding = Encoding.UTF8;
            }

            public static void Clear() => Console.Write("\n\n");

            private static void InitializeOutStream()
            {
                BaseFunctions.ConsoleHelper.fwriter = BaseFunctions.ConsoleHelper.CreateFileStream("CONOUT$", 1073741824U, 2U, FileAccess.Write);
                if (BaseFunctions.ConsoleHelper.fwriter == null)
                    return;
                BaseFunctions.ConsoleHelper.writer = new StreamWriter((Stream)BaseFunctions.ConsoleHelper.fwriter)
                {
                    AutoFlush = true
                };
                Console.SetOut((TextWriter)BaseFunctions.ConsoleHelper.writer);
                Console.SetError((TextWriter)BaseFunctions.ConsoleHelper.writer);
            }

            private static void InitializeInStream()
            {
                FileStream fileStream = BaseFunctions.ConsoleHelper.CreateFileStream("CONIN$", 2147483648U, 1U, FileAccess.Read);
                if (fileStream == null)
                    return;
                Console.SetIn((TextReader)new StreamReader((Stream)fileStream));
            }

            private static FileStream CreateFileStream(
              string name,
              uint win32DesiredAccess,
              uint win32ShareMode,
              FileAccess dotNetFileAccess)
            {
                SafeFileHandle handle = new SafeFileHandle((IntPtr)(long)BaseFunctions.CreateFileW(name, win32DesiredAccess, win32ShareMode, 0U, 3U, 128U, 0U), true);
                return !handle.IsInvalid ? new FileStream(handle, dotNetFileAccess) : (FileStream)null;
            }
        }

        public class ProcInfo
        {
            public Process processRef;
            public ulong processId;
            public string processName;
            public string windowName;
            public ulong handle;
            public ulong baseModule;
            private int nothing;

            public ProcInfo()
            {
                this.processRef = (Process)null;
                this.processId = 0UL;
                this.handle = 0UL;
            }

            public bool isOpen()
            {
                try
                {
                    if (this.processRef == null || this.processRef.HasExited || this.processRef.Id == 0)
                        return false;
                    if (this.processRef.Handle == IntPtr.Zero)
                        return false;
                }
                catch (InvalidOperationException ex)
                {
                    return false;
                }
                catch (Exception ex)
                {
                    return false;
                }
                return this.processId > 0UL && this.handle > 0UL;
            }

            public BaseFunctions.MEMORY_BASIC_INFORMATION getPage(ulong address)
            {
                BaseFunctions.MEMORY_BASIC_INFORMATION lpBuffer = new BaseFunctions.MEMORY_BASIC_INFORMATION();
                long num = (long)BaseFunctions.VirtualQueryEx(this.handle, address, out lpBuffer, 28U);
                return lpBuffer;
            }

            public bool isAccessible(ulong address)
            {
                BaseFunctions.MEMORY_BASIC_INFORMATION page = this.getPage(address);
                uint protect = page.Protect;
                if (page.State != 4096U)
                    return false;
                return protect == 4U || protect == 2U || protect == 64U || protect == 32U;
            }

            public uint setPageProtect(ulong address, int size, uint protect)
            {
                uint lpOldProtect = 0;
                BaseFunctions.VirtualProtectEx(this.handle, address, size, protect, ref lpOldProtect);
                return lpOldProtect;
            }

            public bool writeByte(ulong address, byte value)
            {
                byte[] lpBuffer = new byte[1] { value };
                return BaseFunctions.WriteProcessMemory(this.handle, address, lpBuffer, lpBuffer.Length, ref this.nothing);
            }

            public bool writeBytes(ulong address, byte[] bytes, int count = -1)
            {
                return BaseFunctions.WriteProcessMemory(this.handle, address, bytes, count == -1 ? bytes.Length : count, ref this.nothing);
            }

            public bool writeString(ulong address, string str, int count = -1)
            {
                char[] charArray = str.ToCharArray(0, str.Length);
                List<byte> byteList = new List<byte>();
                foreach (byte num in charArray)
                    byteList.Add(num);
                return BaseFunctions.WriteProcessMemory(this.handle, address, byteList.ToArray(), count == -1 ? byteList.Count : count, ref this.nothing);
            }

            public bool writeWString(ulong address, string str, int count = -1)
            {
                ulong address1 = address;
                foreach (char ch in str.ToCharArray(0, str.Length))
                {
                    this.writeUInt16(address1, Convert.ToUInt16(ch));
                    address1 += 2UL;
                }
                return true;
            }

            public bool writeInt16(ulong address, short value)
            {
                return BaseFunctions.WriteProcessMemory(this.handle, address, BitConverter.GetBytes(value), 2, ref this.nothing);
            }

            public bool writeUInt16(ulong address, ushort value)
            {
                return BaseFunctions.WriteProcessMemory(this.handle, address, BitConverter.GetBytes(value), 2, ref this.nothing);
            }

            public bool writeInt32(ulong address, int value)
            {
                return BaseFunctions.WriteProcessMemory(this.handle, address, BitConverter.GetBytes(value), 4, ref this.nothing);
            }

            public bool writeUInt32(ulong address, uint value)
            {
                return BaseFunctions.WriteProcessMemory(this.handle, address, BitConverter.GetBytes(value), 4, ref this.nothing);
            }

            public bool writeFloat(ulong address, float value)
            {
                return BaseFunctions.WriteProcessMemory(this.handle, address, BitConverter.GetBytes(value), 4, ref this.nothing);
            }

            public bool writeDouble(ulong address, double value)
            {
                return BaseFunctions.WriteProcessMemory(this.handle, address, BitConverter.GetBytes(value), 8, ref this.nothing);
            }

            public bool writeInt64(ulong address, long value)
            {
                return BaseFunctions.WriteProcessMemory(this.handle, address, BitConverter.GetBytes(value), 8, ref this.nothing);
            }

            public bool writeUInt64(ulong address, ulong value)
            {
                return BaseFunctions.WriteProcessMemory(this.handle, address, BitConverter.GetBytes(value), 8, ref this.nothing);
            }

            public byte readByte(ulong address)
            {
                byte[] lpBuffer = new byte[1];
                BaseFunctions.ReadProcessMemory(this.handle, address, lpBuffer, 1, ref this.nothing);
                return lpBuffer[0];
            }

            public byte[] readBytes(ulong address, int count)
            {
                byte[] lpBuffer = new byte[count];
                BaseFunctions.ReadProcessMemory(this.handle, address, lpBuffer, count, ref this.nothing);
                return lpBuffer;
            }

            public string readString(ulong address, int count = -1)
            {
                string str = "";
                ulong address1 = address;
                if (count == -1)
                {
                label_7:
                    for (; address1 != 512UL; address1 += 512UL)
                    {
                        foreach (byte readByte in this.readBytes(address1, 512))
                        {
                            switch (readByte)
                            {
                                case 9:
                                case 10:
                                case 13:
                                case 32:
                                case 33:
                                case 34:
                                case 35:
                                case 36:
                                case 37:
                                case 38:
                                case 39:
                                case 40:
                                case 41:
                                case 42:
                                case 43:
                                case 44:
                                case 45:
                                case 46:
                                case 47:
                                case 48:
                                case 49:
                                case 50:
                                case 51:
                                case 52:
                                case 53:
                                case 54:
                                case 55:
                                case 56:
                                case 57:
                                case 58:
                                case 59:
                                case 60:
                                case 61:
                                case 62:
                                case 63:
                                case 64:
                                case 65:
                                case 66:
                                case 67:
                                case 68:
                                case 69:
                                case 70:
                                case 71:
                                case 72:
                                case 73:
                                case 74:
                                case 75:
                                case 76:
                                case 77:
                                case 78:
                                case 79:
                                case 80:
                                case 81:
                                case 82:
                                case 83:
                                case 84:
                                case 85:
                                case 86:
                                case 87:
                                case 88:
                                case 89:
                                case 90:
                                case 91:
                                case 92:
                                case 93:
                                case 94:
                                case 95:
                                case 96:
                                case 97:
                                case 98:
                                case 99:
                                case 100:
                                case 101:
                                case 102:
                                case 103:
                                case 104:
                                case 105:
                                case 106:
                                case 107:
                                case 108:
                                case 109:
                                case 110:
                                case 111:
                                case 112:
                                case 113:
                                case 114:
                                case 115:
                                case 116:
                                case 117:
                                case 118:
                                case 119:
                                case 120:
                                case 121:
                                case 122:
                                case 123:
                                case 124:
                                case 125:
                                case 126:
                                case 127:
                                    str += ((char)readByte).ToString();
                                    continue;
                                default:
                                    address1 = 0UL;
                                    goto label_7;
                            }
                        }
                    }
                }
                else
                {
                    foreach (byte readByte in this.readBytes(address1, count))
                        str += ((char)readByte).ToString();
                }
                return str;
            }

            public string readWString(ulong address, int count = -1)
            {
                string str = "";
                ulong address1 = address;
                if (count == -1)
                {
                    for (; address1 != 512UL; address1 += 512UL)
                    {
                        byte[] numArray = this.readBytes(address1, 512);
                        for (int index = 0; index < numArray.Length; index += 2)
                        {
                            if (numArray[index] == (byte)0 && numArray[index + 1] == (byte)0)
                            {
                                address1 = 0UL;
                                break;
                            }
                            str += Encoding.Unicode.GetString(new byte[2]
                            {
                numArray[index],
                numArray[index + 1]
                            }, 0, 2);
                        }
                    }
                }
                else
                {
                    byte[] numArray = this.readBytes(address1, count * 2);
                    for (int index = 0; index < numArray.Length; index += 2)
                        str += Encoding.Unicode.GetString(new byte[2]
                        {
              numArray[index],
              numArray[index + 1]
                        }, 0, 2);
                }
                return str;
            }

            public short readInt16(ulong address)
            {
                byte[] lpBuffer = new byte[2];
                BaseFunctions.ReadProcessMemory(this.handle, address, lpBuffer, 2, ref this.nothing);
                return BitConverter.ToInt16(lpBuffer, 0);
            }

            public ushort readUInt16(ulong address)
            {
                byte[] lpBuffer = new byte[2];
                BaseFunctions.ReadProcessMemory(this.handle, address, lpBuffer, 2, ref this.nothing);
                return BitConverter.ToUInt16(lpBuffer, 0);
            }

            public int readInt32(ulong address)
            {
                byte[] lpBuffer = new byte[4];
                BaseFunctions.ReadProcessMemory(this.handle, address, lpBuffer, 4, ref this.nothing);
                return BitConverter.ToInt32(lpBuffer, 0);
            }

            public uint readUInt32(ulong address)
            {
                byte[] lpBuffer = new byte[4];
                BaseFunctions.ReadProcessMemory(this.handle, address, lpBuffer, 4, ref this.nothing);
                return BitConverter.ToUInt32(lpBuffer, 0);
            }

            public float readFloat(ulong address)
            {
                byte[] lpBuffer = new byte[4];
                BaseFunctions.ReadProcessMemory(this.handle, address, lpBuffer, 4, ref this.nothing);
                return BitConverter.ToSingle(lpBuffer, 0);
            }

            public double readDouble(ulong address)
            {
                byte[] lpBuffer = new byte[8];
                BaseFunctions.ReadProcessMemory(this.handle, address, lpBuffer, 8, ref this.nothing);
                return BitConverter.ToDouble(lpBuffer, 0);
            }

            public long readInt64(ulong address)
            {
                byte[] lpBuffer = new byte[8];
                BaseFunctions.ReadProcessMemory(this.handle, address, lpBuffer, 8, ref this.nothing);
                return BitConverter.ToInt64(lpBuffer, 0);
            }

            public ulong readUInt64(ulong address)
            {
                byte[] lpBuffer = new byte[8];
                BaseFunctions.ReadProcessMemory(this.handle, address, lpBuffer, 8, ref this.nothing);
                return BitConverter.ToUInt64(lpBuffer, 0);
            }

            public bool isPrologue(ulong address)
            {
                byte[] numArray = this.readBytes(address, 3);
                return numArray[0] == (byte)139 && numArray[1] == byte.MaxValue && numArray[2] == (byte)85 || address % 16UL <= 0UL && (numArray[0] == (byte)82 && numArray[1] == (byte)139 && numArray[2] == (byte)212 || numArray[0] == (byte)83 && numArray[1] == (byte)139 && numArray[2] == (byte)220 || numArray[0] == (byte)85 && numArray[1] == (byte)139 && numArray[2] == (byte)236 || numArray[0] == (byte)86 && numArray[1] == (byte)139 && numArray[2] == (byte)244 || numArray[0] == (byte)87 && numArray[1] == (byte)139 && numArray[2] == byte.MaxValue);
            }

            public bool isEpilogue(ulong address)
            {
                byte num1 = this.readByte(address);
                switch (num1)
                {
                    case 194:
                    case 195:
                    case 204:
                        byte num2 = this.readByte(address - 1UL);
                        int num3;
                        switch (num2)
                        {
                            case 90:
                            case 91:
                                num3 = 0;
                                break;
                            default:
                                num3 = (uint)num2 - 93U > 2U ? 1 : 0;
                                break;
                        }
                        if (num3 == 0)
                        {
                            if (num1 == (byte)194)
                            {
                                ushort num4 = this.readUInt16(address + 1UL);
                                if ((int)num4 % 4 == 0 && num4 > (ushort)0)
                                    return true;
                            }
                            return true;
                        }
                        break;
                    case 201:
                        return true;
                }
                return false;
            }

            private bool isValidCode(ulong address)
            {
                return this.readUInt64(address) != 0UL || this.readUInt64(address + 8UL) > 0UL;
            }

            public ulong gotoPrologue(ulong address)
            {
                ulong address1 = address;
                if (this.isPrologue(address1))
                    return address1;
                while (!this.isPrologue(address1) && this.isValidCode(address))
                    address1 = address1 % 16UL == 0UL ? address1 - 16UL : address1 - address1 % 16UL;
                return address1;
            }

            public ulong gotoNextPrologue(ulong address)
            {
                ulong address1 = address;
                if (this.isPrologue(address1))
                    address1 += 16UL;
                while (!this.isPrologue(address1) && this.isValidCode(address1))
                    address1 = address1 % 16UL != 0UL ? address1 + address1 % 16UL : address1 + 16UL;
                return address1;
            }
        }
    }
}
