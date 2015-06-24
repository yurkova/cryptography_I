using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Week2
{
    public abstract class AesAlgorithm
    {
        private const int DefaultKeySizeInBits = 128;
        private const int DefaultBlockSizeInBits = 128;


        protected AesAlgorithm()
        {
            KeySize = DefaultKeySizeInBits / 8;
            BlockSize = DefaultBlockSizeInBits / 8;
        }

        protected AesAlgorithm(int keySizeInBits, int blockSizeInbits)
        {
            KeySize = keySizeInBits / 8;
            BlockSize = blockSizeInbits / 8;
        }

        protected int KeySize { get; private set; }
        protected int BlockSize { get; private set; }


        public string EncryptMessage(string keyString, string plainText)
        {
            var key = GetBytesFromHexString(keyString);
            var pt = GetBytesFromString(plainText);
            return EncryptByBlocks(key, pt.ToList());
        }

        protected abstract string EncryptByBlocks(byte[] key,
            List<byte> plainText);

        public string DecryptMessage(string keyString, string inputText)
        {
            var key = GetBytesFromHexString(keyString);
            var iv = GetBytesFromHexString(inputText.Substring(0,
                BlockSize * 2));
            var cipherText = GetBytesFromHexString(inputText.Substring(
                BlockSize * 2, inputText.Length - BlockSize * 2));
            return DecryptByBlocks(key, iv, cipherText.ToList());
        }

        protected abstract string DecryptByBlocks(byte[] key, byte[] iv,
            List<byte> cipherText);


        private static byte[] GetBytesFromHexString(string hexString)
        {
            return Enumerable.Range(0, hexString.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hexString.Substring(x, 2), 16))
                .ToArray();
        }

        private static IEnumerable<byte> GetBytesFromString(string plainText)
        {
            return plainText.Select(c => (byte) c).ToList();
        }

        protected static StringBuilder BytesToHexString(IEnumerable<byte> bytes)
        {
            var hexStr = new StringBuilder();
            foreach (var b in bytes)
            {
                hexStr.Append(b.ToString("x2"));
            }
            return hexStr;
        }

        protected static StringBuilder BytesToPlainText(IEnumerable<byte> bytes)
        {
            var text = new StringBuilder();
            foreach (var b in bytes)
            {
                text.Append((char) b);
            }
            return text;
        }

        protected byte[] DetachBlock(List<byte> bytes)
        {
            var block = bytes.GetRange(0, Math.Min(BlockSize, bytes.Count));
            bytes.RemoveRange(0, Math.Min(BlockSize, bytes.Count));
            return block.ToArray();
        }
    }
}