using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using static SharpSam.Native;

namespace SharpSam
{
    internal class Token
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public unsafe byte* lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [Flags]
        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        [Flags]
        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation,
            TOKEN_DUPLICATE = 2

        }
        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, LogonFlags dwLogonFlags, string lpApplicationName, string lpCommandLine, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            UInt32 TokenType,
            out IntPtr phNewToken);


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [Flags]
        public enum LogonFlags
        {
            LOGON_WITH_PROFILE = 0x00000001,
            LOGON_NETCREDENTIALS_ONLY = 0x00000002
        }

        [Flags]
        public enum CreationFlags
        {
            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }


        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetThreadToken(IntPtr pHandle,
            IntPtr hToken);

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        private static IntPtr GetCurrentProcessToken()
        {

            IntPtr currentProcessToken = new IntPtr();
            if (!Native.OpenProcessToken(Process.GetCurrentProcess().Handle, Native.TOKEN_ALL_ACCESS, out currentProcessToken))
            {
                Console.WriteLine("Error OpenProcessToken " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return IntPtr.Zero;
            }
            return currentProcessToken;
        }

        public static bool priv_simple()
        {

            string Privilege = "SeDebugPrivilege";
            IntPtr hToken = GetCurrentProcessToken();
            Native.LUID luid = new Native.LUID();
            if (!Native.LookupPrivilegeValue(null, Privilege, ref luid))
            {
                Console.WriteLine("Error LookupPrivilegeValue" + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }

            Native.LUID_AND_ATTRIBUTES luidAndAttributes = new Native.LUID_AND_ATTRIBUTES();
            luidAndAttributes.Luid = luid;
            luidAndAttributes.Attributes = Native.SE_PRIVILEGE_ENABLED;

            Native.TOKEN_PRIVILEGES newState = new Native.TOKEN_PRIVILEGES();
            newState.PrivilegeCount = 1;
            newState.Privileges = luidAndAttributes;



            UInt32 returnLength = 0;
            Native.TOKEN_PRIVILEGES previousState = new Native.TOKEN_PRIVILEGES();
            if (AdjustTokenPrivileges(hToken, false, ref newState, (UInt32)Marshal.SizeOf(newState), ref previousState, out returnLength))
            {
                Console.WriteLine("RtlAdjustPrivilege! {0}", Native.SE_PRIVILEGE_ENABLED);
                return true;
            }
            Console.WriteLine("adjust failed :o");
            return false;
        }

        public static bool isSystem()
        {
            WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent();
            if (currentIdentity != null && currentIdentity.Name.Equals(@"NT AUTHORITY\SYSTEM", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            return false;
        }

    }

}
