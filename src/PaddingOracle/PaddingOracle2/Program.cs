using System.Security.Cryptography;
using System.Text;

namespace PaddingOracle2
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var strToBeEncrypted = "abcdefghijklmnopabcdefghijklmnopabcde";
            var iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            var key = Encoding.ASCII.GetBytes("1234567890123456");
            
            var cipher = Oracle.Encrypt(strToBeEncrypted, iv, key);

            key = Encoding.ASCII.GetBytes("1234567890123453");
            var size = PaddingOracle.GetPaddingSize(cipher, key); // if size = 16 the 

            

            var paddingError = PaddingOracle.HasPaddingError(cipher, iv);
            Console.WriteLine(paddingError);
            paddingError = PaddingOracle.HasPaddingError(cipher, new byte[] { 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
            Console.WriteLine(paddingError);
            paddingError = PaddingOracle.HasPaddingError(cipher, new byte[] { 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0 });
            Console.WriteLine(paddingError);
        }

        
    }
}