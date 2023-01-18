using System.Security.Cryptography;
using System.Text;

namespace PaddingOracle2
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var strToBeEncrypted = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmn";
            var iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            
            var cipher = Oracle.Encrypt(strToBeEncrypted, iv);

            var plainText = PaddingOracle.GetPlainText(cipher, iv);

        }

        
    }
}