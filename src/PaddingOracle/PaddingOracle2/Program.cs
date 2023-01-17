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

            PaddingOracle.GetPlainText(cipher);

            var size = PaddingOracle.GetPaddingSize(cipher); // if size = 16 the 

            

            var paddingError = PaddingOracle.HasPaddingError(cipher, iv);
            Console.WriteLine(paddingError);
            paddingError = PaddingOracle.HasPaddingError(cipher, new byte[] { 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
            Console.WriteLine(paddingError);
            paddingError = PaddingOracle.HasPaddingError(cipher, new byte[] { 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0 });
            Console.WriteLine(paddingError);
        }

        
    }
}