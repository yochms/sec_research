using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PaddingOracle2
{
    public class PaddingOracle
    {
        public static bool HasPaddingError(byte[] cipherText, byte[] iv, byte[] key = null)
        {
            try
            {
                Oracle.Decrypt(cipherText, iv, key);
                return false;
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
                return true;
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

        public static int GetPaddingSize(byte[] cipher, byte[] key = null)
        {
            // TODO what if block size is 1?

            const int BlockSize = 16;

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
                var result = HasPaddingError(lastBlock, temp, key);
                if (result)
                {
                    paddingStartsAt = i++;
                    break;
                }
            }
            return BlockSize - paddingStartsAt;
        }
    }
}
