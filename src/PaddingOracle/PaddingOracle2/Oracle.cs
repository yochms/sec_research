using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PaddingOracle2
{
    public class Oracle
    {
        private static byte[] key = Encoding.ASCII.GetBytes("1234567890123453");

        public static byte[] Encrypt(string plainTxt, byte[] iv)
        {
            byte[] encrypted;

            using (AesManaged aes = new AesManaged())
            {
                aes.IV = iv;
                aes.Key = key;
                Console.WriteLine(aes.BlockSize);
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;
                ICryptoTransform ict = aes.CreateEncryptor();
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, ict, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainTxt);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }

            }
            return encrypted;
        }

        public static string Decrypt(byte[] cipher, byte[] iv)
        {
            string plainText = string.Empty;
            // Try to decrypt the cipher
            using (AesManaged aes = new AesManaged())
            {
                aes.IV = iv;
                aes.Key = key;
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;

                ICryptoTransform decryptor = aes.CreateDecryptor();

                using (MemoryStream msDecrypt = new MemoryStream(cipher))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plainText = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plainText;
        }
    }
}
