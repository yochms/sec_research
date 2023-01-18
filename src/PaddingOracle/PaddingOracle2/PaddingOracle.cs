using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace PaddingOracle2
{
    public class PaddingOracle
    {
        const int BlockSize = 16;

        public static bool HasPaddingError(byte[] cipherText, byte[] iv)
        {
            try
            {
                Oracle.Decrypt(cipherText, iv);
                return false;
            }
            catch (Exception ex)
            {
                //Console.WriteLine(ex.Message);

                if (ex.Message.Contains("Padding is invalid and cannot be removed"))
                {
                    return true;
                }
                return false;
            }
        }

        public static List<byte[]> GetBlockList(byte[] cipherText, int blockSize = 16) // for AES
        {
            int blockCount = cipherText.Length / blockSize;
            List<byte[]> blocks = new List<byte[]>();
            for (int i = 0; i < blockCount; i++)
            {
                var block = new byte[blockSize];
                Array.Copy(cipherText, i * blockSize, block, 0, blockSize);
                blocks.Add(block);
            }

            return blocks;
        }

        // Not really relevant to the attack?
        public static int GetPaddingSize(byte[] cipher)
        {
            // TODO what if block size is 1?
            var blockList = GetBlockList(cipher);
            var blockCount = blockList.Count;
            var lastBlock = new byte[BlockSize];
            Array.Copy(cipher, (blockCount - 1) * BlockSize, lastBlock, 0, BlockSize);
            var lastBlockIv = new byte[BlockSize];
            Array.Copy(cipher, (blockCount - 2) * BlockSize, lastBlockIv, 0, BlockSize);
            int paddingStartsAt = 0;
            for (int i = 0; i < BlockSize; i++)
            {
                var temp = new byte[BlockSize];
                Array.Copy(lastBlockIv, temp, BlockSize);
                temp[i] = 0;
                var result = HasPaddingError(lastBlock, temp);
                if (result)
                {
                    paddingStartsAt = i++;
                    break;
                }
            }
            return BlockSize - paddingStartsAt;
        }

        public static string GetPlainText(byte[] cipher, byte[] iv)
        {
            var blockList = GetBlockList(cipher);
            var blockCount = blockList.Count;
            var decryptedStack = new Stack<byte>();

            for (int i = blockList.Count - 1; i >= 0; i--)
            {
                var decryptedArray = new byte[BlockSize];
                var blockToBeProcessed = new byte[BlockSize * 2];                
                
                //Array.Copy(blockList[i - 1], blockToBeProcessed, BlockSize);
                Array.Copy(blockList[i], 0, blockToBeProcessed, BlockSize, BlockSize);

                for (int paddingSize = 1; paddingSize <= BlockSize; paddingSize++)
                {
                    var hit = -1;

                    for (int j = 1; j < 255; j++)
                    {
                        blockToBeProcessed[BlockSize - paddingSize] = (byte)j;

                        var hasPaddingError = HasPaddingError(blockToBeProcessed, new byte[BlockSize]);
                        if (!hasPaddingError)
                        {
                            hit = j;
                            break;
                        }
                    }

                    int decryptedValue;

                    if (i == 0)
                    {
                        decryptedValue = paddingSize ^ iv[BlockSize - paddingSize] ^ hit;
                        decryptedArray[paddingSize - 1] = (byte)decryptedValue;
                        for (int x = 1; x <= paddingSize; x++)
                        {
                            blockToBeProcessed[BlockSize - x] = (byte)(paddingSize + 1 ^ decryptedArray[x - 1] ^ iv[BlockSize - x]);
                        }
                    }
                    else
                    {
                        decryptedValue = paddingSize ^ blockList[i - 1][BlockSize - paddingSize] ^ hit;
                        decryptedArray[paddingSize - 1] = (byte)decryptedValue;
                        for (int x = 1; x <= paddingSize; x++)
                        {
                            blockToBeProcessed[BlockSize - x] = (byte)(paddingSize + 1 ^ decryptedArray[x - 1] ^ blockList[i - 1][BlockSize - x]);
                        }
                    }
                    
                    decryptedStack.Push((byte)decryptedValue);
                }               
            }

            string text = string.Empty;
            var index = 0;
            var temp = new byte[decryptedStack.Count];
            while (decryptedStack.Count != 0)
            {
                temp[index] = decryptedStack.Pop();
                index++;
            }
            text = Encoding.ASCII.GetString(temp);
            return text;            
        }
    }
}
