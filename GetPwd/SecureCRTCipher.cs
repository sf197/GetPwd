using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace GetPwd
{
    class SecureCRTCipher
    {
        private static byte[] IV = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        private static byte[] Key1 = { 0x24, 0xa6, 0x3d, 0xde, 0x5b, 0xd3, 0xb3, 0x82, 0x9c, 0x7e, 0x06, 0xf4, 0x08, 0x16, 0xaa, 0x07 };
        private static byte[] Key2 = { 0x5f, 0xb0, 0x45, 0xa2, 0x94, 0x17, 0xd9, 0x16, 0xc6, 0xc6, 0xa2, 0xff, 0x06, 0x41, 0x82, 0xb7 };
        private static byte[] Key_V2 = { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };

        private static byte[] fromhex(String hex) {
            byte[] mybyte = new byte[int.Parse(Math.Ceiling(hex.Length / 2.0).ToString())];
            for (int i = 0; i <mybyte.Length;i++) {
                int len = 2 <= hex.Length ? 2 : hex.Length;
                mybyte[i] = Convert.ToByte(hex.Substring(0, len),16);
                hex = hex.Substring(len, hex.Length - len);
            }
            return mybyte;
        }

        private static string Findnull(byte[] dec) {
            List<byte> ret = new List<byte>();
            string str = "";
            for (int i=0; i < dec.Length; i++)
            {
                if (dec[i] == 0) {
                    if (dec[i+1] == 0) {
                        i++;
                        continue;
                    }
                }
                str += (char)dec[i];
                ret.Add(dec[i]);
            }
            byte[] test = ret.Where(x => x != 0).ToArray();
            return System.Text.Encoding.Default.GetString(test);
        }

        private static string AESDecrypt(string decryptStr, byte[] key)
        {
            var _aes = new AesCryptoServiceProvider();
            _aes.BlockSize = 128;
            _aes.KeySize = 256;
            _aes.Key = key;
            _aes.IV = (byte[])(object)new sbyte[16];//Encoding.UTF8.GetBytes(IV);
            _aes.Padding = PaddingMode.PKCS7;
            _aes.Mode = CipherMode.CBC;

            byte[] decryptBytes = System.Convert.FromBase64String(decryptStr);

            var _crypto = _aes.CreateDecryptor(_aes.Key, _aes.IV);
            byte[] decrypted = _crypto.TransformFinalBlock(decryptBytes, 0, decryptBytes.Length);
            _crypto.Dispose();
            return Encoding.UTF8.GetString(decrypted);
            
        }

        public static string AESEncrypt(string encryptStr)
        {
            var _aes = new AesCryptoServiceProvider();
            _aes.BlockSize = 128;
            _aes.KeySize = 256;
            _aes.Key = Key_V2;
            _aes.IV = (byte[])(object)new sbyte[16];//Encoding.UTF8.GetBytes(IV);
            _aes.Padding = PaddingMode.PKCS7;
            _aes.Mode = CipherMode.CBC;

            var _crypto = _aes.CreateEncryptor(_aes.Key, _aes.IV);
            byte[] encrypted = _crypto.TransformFinalBlock(Encoding.UTF8.GetBytes(encryptStr), 0, Encoding.UTF8.GetBytes(encryptStr).Length);

            _crypto.Dispose();

            return System.Convert.ToBase64String(encrypted);
        }

        public static string V2CRT(string str) {
            byte[] IV = { 
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            byte[] ciphered_bytes = fromhex(str);
            if (ciphered_bytes.Length <= 8)
            {
                return null;
            }
            return AESDecrypt(Convert.ToBase64String(ciphered_bytes), Key_V2);
        }

        public static string PasswordCRT(string str) {
            byte[] ciphered_bytes = fromhex(str);
            if (ciphered_bytes.Length <= 8) {
                return null;
            }

            BlowFishC algo = new BlowFishC(Key1);
            algo.IV = IV;
            byte[] decryptedTxt = algo.Decrypt_CBC(ciphered_bytes);
            decryptedTxt = decryptedTxt.Skip(4).Take(decryptedTxt.Length - 8).ToArray();

            algo = new BlowFishC(Key2);
            algo.IV = IV;
            ciphered_bytes = algo.Decrypt_CBC(decryptedTxt);
            string ciphered = Findnull(ciphered_bytes);
            
            return ciphered;
        }

    }
}
