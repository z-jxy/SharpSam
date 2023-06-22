﻿using System;
using System.Runtime.InteropServices;

namespace SharpSam.Crypto
{
    internal class AES
    {
        public const int CRYPT_MODE_CBC = 1;       // Cipher block chaining
        public const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
        public const int PROV_RSA_AES = 24;
        public const int ALG_SID_AES_128 = 14;
        public const int ALG_SID_AES_256 = 16;
        public const int ALG_TYPE_BLOCK = (3 << 9);
        public const int ALG_CLASS_DATA_ENCRYPT = (3 << 13);
        public const int ALG_SID_3DES = 3;
        public const int ALG_CLASS_KEY_EXCHANGE = (5 << 13);
        public const int ALG_TYPE_RSA = (2 << 9);
        public const int ALG_SID_RSA_ANY = 0;
        public const int CALG_AES_128 = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_128);
        public const int CALG_AES_256 = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256);
        public const int KP_MODE = 4;       // Mode of the cipher
        public const int KP_IV = 1;       // Initialization vector
        public const int CRYPT_NEWKEYSET = 0x00000008;
        public const int AT_KEYEXCHANGE = 1;
        public const int CRYPT_EXPORTABLE = 0x00000001;
        public const int RSA1024BIT_KEY = 0x04000000;
        public const int PRIVATEKEYBLOB = 0x7;
        public const int SIMPLEBLOB = 0x1;
        public const int CUR_BLOB_VERSION = 2;
        public const int PLAINTEXTKEYBLOB = 0x8;
        public const int CRYPT_MODE_ECB = 2;

        const int PP_CONTAINER = 6;
        const int PP_NAME = 4;
        const int PP_PROVTYPE = 16;
        const int CRYPT_DELETEKEYSET = 0x00000010;

        const int AES_256_KEY_SIZE = (256 / 8);

        public const int CALG_3DES = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_3DES);
        const int CALG_RSA_KEYX = (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | ALG_SID_RSA_ANY);

        [StructLayout(LayoutKind.Sequential)]
        public struct GENERICKEY_BLOB
        {
            public BLOBHEADER Header;
            public uint dwKeyLen;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BLOBHEADER
        {
            public byte bType;
            public byte bVersion;
            public ushort reserved;
            public uint aiKeyAlg;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PUBLICKEYSTRUC
        {
            public byte bType;
            public byte bVersion;
            public ushort reserved;
            public uint aiKeyAlg;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NT6_CLEAR_SECRET
        {
            IntPtr SecretSize;
            IntPtr unk0;
            IntPtr unk1;
            IntPtr unk2;
            byte[] Secret;
        };
        public static int LAZY_NT6_IV_SIZE = 32;

        [StructLayout(LayoutKind.Sequential)]
        public struct NT6_HARD_SECRET
        {
            public IntPtr version;
            public Guid KeyId;
            public IntPtr algorithm;
            public IntPtr flag;
            public byte[] lazyiv;
            public NT6_CLEAR_SECRET clearSecret;
            public byte[] encryptedSecret;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct NT6_SYSTEM_KEY
        {
            public Guid KeyId;
            public IntPtr KeyType;
            public IntPtr KeySize;
            public byte[] Key;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct _NT6_SYSTEM_KEYS
        {
            public IntPtr unkType0;
            public Guid CurrentKeyID;
            public IntPtr unkType1;
            public IntPtr nbKeys;
            public NT6_SYSTEM_KEY Keys;
        };



        [StructLayout(LayoutKind.Sequential)]
        public struct RSAPUBKEY
        {
            public uint magic;                  // Has to be RSA1
            public uint bitlen;                 // # of bits in modulus
            public uint pubexp;                 // public exponent
                                                // Modulus data follows
        }



        public static bool kull_m_crypto_genericAES128Decrypt(IntPtr pKey, IntPtr pIV, IntPtr pData, uint dwDataLen, ref IntPtr pOut, ref uint dwOutLen)
        {
            bool status = false;
            IntPtr hProv = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            uint mode = CRYPT_MODE_CBC;
            byte[] bytes = BitConverter.GetBytes(mode);
            GCHandle pinnedArray = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            IntPtr pMode = pinnedArray.AddrOfPinnedObject();
            if (Native.CryptAcquireContextA(ref hProv, null, null, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            {
                if (kull_m_crypto_hkey(hProv, CALG_AES_128, pKey, 16, 0, ref hKey, IntPtr.Zero))
                {
                    if (Native.CryptSetKeyParam(hKey, KP_MODE, pMode, 0))
                    {
                        if (Native.CryptSetKeyParam(hKey, KP_IV, pIV, 0))
                        {
                            pOut = Marshal.AllocHGlobal((int)dwDataLen);
                            if (pOut != IntPtr.Zero)
                            {
                                dwOutLen = dwDataLen;
                                byte[] buffer = new byte[(int)dwDataLen];
                                Marshal.Copy(pData, buffer, 0, (int)dwDataLen);
                                Marshal.Copy(buffer, 0, pOut, (int)dwDataLen);
                                //GCHandle pinnedArrayOut = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                                //pOut = pinnedArray.AddrOfPinnedObject();
                                if (!(status = Native.CryptDecrypt(hKey, IntPtr.Zero, true, 0, pOut, ref dwOutLen)))
                                {
                                    Console.WriteLine("CryptDecrypt " + Marshal.GetLastWin32Error());
                                    //Marshal.FreeHGlobal(pOut);
                                    dwOutLen = 0;
                                }
                            }
                        }
                        else Console.WriteLine("CryptSetKeyParam (IV)");
                    }
                    else Console.WriteLine("CryptSetKeyParam (MODE)");
                    Native.CryptDestroyKey(hKey);
                }
                else Console.WriteLine("kull_m_crypto_hkey");
                Native.CryptReleaseContext(hProv, 0);
            }
            else Console.WriteLine("CryptAcquireContext");
            return status;
        }

        public static bool kull_m_crypto_hkey(IntPtr hProv, uint calgid, IntPtr key, uint keyLen, uint flags, ref IntPtr hKey, IntPtr hSessionProv)
        {
            bool status = true;
            IntPtr keyBlob = IntPtr.Zero;
            uint szBlob = (uint)(Marshal.SizeOf(typeof(GENERICKEY_BLOB)) + (int)keyLen);
            GENERICKEY_BLOB gb = new GENERICKEY_BLOB();
            if (calgid != CALG_3DES)
            {
                keyBlob = Marshal.AllocHGlobal((int)szBlob);
                if (keyBlob != IntPtr.Zero)
                {
                    gb.Header.bType = PLAINTEXTKEYBLOB;
                    gb.Header.bVersion = CUR_BLOB_VERSION;
                    gb.Header.reserved = 0;
                    gb.Header.aiKeyAlg = calgid;
                    gb.dwKeyLen = keyLen;
                    Marshal.StructureToPtr(gb, keyBlob, false);
                    byte[] buffer = new byte[gb.dwKeyLen];
                    Marshal.Copy(key, buffer, 0, (int)gb.dwKeyLen);
                    Marshal.Copy(buffer, 0, IntPtr.Add(keyBlob, Marshal.SizeOf(typeof(GENERICKEY_BLOB))), (int)gb.dwKeyLen);
                    status = Native.CryptImportKey(hProv, keyBlob, szBlob, IntPtr.Zero, flags, ref hKey);
                    Marshal.FreeHGlobal(keyBlob);
                }
            }
            else if (hSessionProv != IntPtr.Zero)
                status = kull_m_crypto_hkey_session(calgid, key, keyLen, flags, hKey, hSessionProv);

            return status;
        }

        public static void ZeroMemory(IntPtr p, int len)
        {
            byte[] ar = new byte[len];
            Marshal.Copy(ar, 0, p, len);
        }
        public static bool kull_m_crypto_hkey_session(uint calgid, IntPtr key, uint keyLen, uint flags, IntPtr hSessionKey, IntPtr hSessionProv)
        {
            bool status = false;
            IntPtr keyblob, pbSessionBlob, ptr;
            uint dwkeyblob = 0;
            uint dwLen = 0;
            string container;
            IntPtr hPrivateKey;
            RSAPUBKEY pubk = new RSAPUBKEY();

            container = Guid.NewGuid().ToString();

            if (Native.CryptAcquireContextA(ref hSessionProv, container, null, PROV_RSA_AES, CRYPT_NEWKEYSET))
            {
                hPrivateKey = IntPtr.Zero;
                if (Native.CryptGenKey(hSessionProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE | (RSA1024BIT_KEY / 2), hPrivateKey)) // 1024
                {
                    if (Native.CryptExportKey(hPrivateKey, IntPtr.Zero, PRIVATEKEYBLOB, 0, IntPtr.Zero, ref dwkeyblob))
                    {
                        keyblob = Marshal.AllocHGlobal((int)dwkeyblob);
                        if (keyblob != IntPtr.Zero)
                        {
                            if (Native.CryptExportKey(hPrivateKey, IntPtr.Zero, PRIVATEKEYBLOB, 0, keyblob, ref dwkeyblob))
                            {
                                Native.CryptDestroyKey(hPrivateKey);
                                hPrivateKey = IntPtr.Zero;
                                Marshal.PtrToStructure(IntPtr.Add(keyblob, Marshal.SizeOf(typeof(PUBLICKEYSTRUC))), pubk);
                                dwLen = pubk.bitlen / 8;
                                pubk.pubexp = 1;//NOTE
                                ptr = IntPtr.Add(keyblob, Marshal.SizeOf(typeof(PUBLICKEYSTRUC)) + Marshal.SizeOf(typeof(RSAPUBKEY)));

                                ptr = IntPtr.Add(ptr, 2 * (int)dwLen); // Skip pubexp, modulus, prime1, prime2
                                Marshal.WriteByte(ptr, 1); //*ptr = 1; // Convert exponent1 to 1
                                ZeroMemory(IntPtr.Add(ptr, 1), ((int)dwLen / 2) - 1);
                                ptr = IntPtr.Add(ptr, (int)dwLen / 2); //ptr += dwLen / 2; // Skip exponent1
                                Marshal.WriteByte(ptr, 1); //*ptr = 1; // Convert exponent2 to 1
                                ZeroMemory(IntPtr.Add(ptr, 1), ((int)dwLen / 2) - 1);
                                ptr = IntPtr.Add(ptr, (int)dwLen); //ptr += dwLen; // Skip exponent2, coefficient
                                Marshal.WriteByte(ptr, 1); //*ptr = 1; // Convert privateExponent to 1
                                ZeroMemory(IntPtr.Add(ptr, 1), ((int)dwLen / 2) - 1);

                                if (Native.CryptImportKey(hSessionProv, keyblob, dwkeyblob, IntPtr.Zero, 0, ref hPrivateKey))
                                {
                                    dwkeyblob = (uint)((1024 / 2 / 8) + sizeof(uint) + Marshal.SizeOf(typeof(BLOBHEADER))); // 1024
                                    pbSessionBlob = Marshal.AllocHGlobal((int)dwkeyblob);
                                    BLOBHEADER bSessionBlob = new BLOBHEADER();
                                    if (pbSessionBlob != IntPtr.Zero)
                                    {
                                        bSessionBlob.bType = SIMPLEBLOB;
                                        bSessionBlob.bVersion = CUR_BLOB_VERSION;
                                        bSessionBlob.reserved = 0;
                                        bSessionBlob.aiKeyAlg = calgid;
                                        Marshal.StructureToPtr(bSessionBlob, pbSessionBlob, false);
                                        ptr = IntPtr.Add(pbSessionBlob, Marshal.SizeOf(typeof(BLOBHEADER)));
                                        Marshal.WriteInt32(ptr, CALG_RSA_KEYX);// *(ALG_ID*)ptr = CALG_RSA_KEYX;
                                        ptr = IntPtr.Add(ptr, sizeof(uint));// ptr += sizeof(ALG_ID);

                                        for (int i = 0; i < keyLen; i++)
                                            Marshal.WriteByte(IntPtr.Add(ptr, i), Marshal.ReadByte(IntPtr.Add(key, (int)keyLen - i - 1)));//ptr[i] = ((LPCBYTE)key)[keyLen - i - 1];
                                        ptr = IntPtr.Add(ptr, (int)keyLen + 1); //ptr += (keyLen + 1);
                                        for (int i = 0; i < dwkeyblob - (sizeof(uint) + Marshal.SizeOf(typeof(BLOBHEADER)) + keyLen + 3); i++)
                                            if (Marshal.ReadByte(IntPtr.Add(ptr, i)) == 0) Marshal.WriteByte(IntPtr.Add(ptr, i), 0x42);//ptr[i] = 0x42;
                                        Marshal.WriteByte(IntPtr.Add(pbSessionBlob, (int)dwkeyblob - 2), 2);//pbSessionBlob[dwkeyblob - 2] = 2;

                                        status = Native.CryptImportKey(hSessionProv, pbSessionBlob, dwkeyblob, hPrivateKey, flags, ref hSessionKey);
                                        Marshal.FreeHGlobal(pbSessionBlob);
                                    }
                                }
                            }
                            Marshal.FreeHGlobal(keyblob);
                        }
                    }
                }
                if (hPrivateKey != IntPtr.Zero)
                    Native.CryptDestroyKey(hPrivateKey);
                if (!status)
                    kull_m_crypto_close_hprov_delete_container(hSessionProv);
            }


            return status;
        }

        public static bool kull_m_crypto_close_hprov_delete_container(IntPtr hProv)
        {
            bool status = false;
            uint provtype = 1;
            IntPtr container = IntPtr.Zero;
            IntPtr provider = IntPtr.Zero;
            uint cbData = 0;
            uint simpleDWORD = 0;
            if (kull_m_crypto_CryptGetProvParam(hProv, PP_CONTAINER, false, container, ref cbData, ref simpleDWORD))
            {
                if (kull_m_crypto_CryptGetProvParam(hProv, PP_NAME, false, provider, ref cbData, ref simpleDWORD))
                {
                    if (kull_m_crypto_CryptGetProvParam(hProv, PP_PROVTYPE, false, IntPtr.Zero, ref cbData, ref provtype))
                    {
                        Native.CryptReleaseContext(hProv, 0);
                        string containerstr = Marshal.PtrToStringAnsi(container);
                        string providerstr = Marshal.PtrToStringAnsi(provider);
                        status = Native.CryptAcquireContextA(ref hProv, containerstr, providerstr, provtype, CRYPT_DELETEKEYSET);
                    }
                    Marshal.FreeHGlobal(provider);
                }
            }
            if (!status)
                Console.WriteLine("CryptGetProvParam/CryptAcquireContextA");
            return status;
        }

        public static bool kull_m_crypto_CryptGetProvParam(IntPtr hProv, uint dwParam, bool withError, IntPtr data, ref uint cbData, ref uint simpleDWORD)
        {
            bool status = false;
            uint dwSizeNeeded = 0; ;
            IntPtr psimpleDWORD = Marshal.AllocHGlobal(sizeof(uint));
            if (simpleDWORD != 0)
            {
                dwSizeNeeded = sizeof(uint);
                if (Native.CryptGetProvParam(hProv, dwParam, psimpleDWORD, ref dwSizeNeeded, 0))
                {
                    simpleDWORD = (uint)Marshal.ReadInt32(psimpleDWORD);
                    status = true;
                }
                else if (withError) Console.WriteLine("CryptGetProvParam(simple DWORD)");
            }
            else
            {
                if (Native.CryptGetProvParam(hProv, dwParam, IntPtr.Zero, ref dwSizeNeeded, 0))
                {
                    data = Marshal.AllocHGlobal((int)dwSizeNeeded);
                    if (data != IntPtr.Zero)
                    {
                        if (Native.CryptGetProvParam(hProv, dwParam, data, ref dwSizeNeeded, 0))
                        {
                            if (cbData != 0)
                                cbData = dwSizeNeeded;
                            status = true;
                        }
                        else
                        {
                            if (withError)
                                Console.WriteLine("CryptGetProvParam(data)");
                            Marshal.FreeHGlobal(data);
                        }
                    }
                }
                else if (withError) Console.WriteLine("CryptGetProvParam(init)");
            }
            return status;
        }
    }
}
