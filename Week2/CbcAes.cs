using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Week2
{
    internal class CbcAes : AesAlgorithm
    {
        protected override string EncryptByBlocks(byte[] key,
            List<byte> plainText)
        {
            var cipherText = new StringBuilder();
            if (plainText.Count % BlockSize == 0)
            {
                AddDummyBlock(plainText);
            }
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.BlockSize = BlockSize * 8;
                aes.KeySize = KeySize * 8;
                aes.Padding = PaddingMode.None;
                aes.Key = key;
                aes.GenerateIV();
                cipherText.Append(BytesToHexString(aes.IV));
                using (var encr = aes.CreateEncryptor())
                {
                    while (plainText.Count != 0)
                    {
                        var block = DetachBlock(plainText);
                        if (block.Length < BlockSize)
                        {
                            block = CompleteBlock(block);
                        }
                        var encrypted = new byte[BlockSize];
                        encr.TransformBlock(block, 0, BlockSize, encrypted, 0);
                        cipherText.Append(BytesToHexString(encrypted));
                        aes.IV = encrypted;
                    }
                }
            }
            return cipherText.ToString();
        }

        protected override string DecryptByBlocks(byte[] key, byte[] iv,
            List<byte> cipherText)
        {
            var message = new StringBuilder();
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.BlockSize = BlockSize * 8;
                aes.KeySize = KeySize * 8;
                aes.Key = key;
                aes.IV = iv;
                aes.Padding = PaddingMode.None;
                using (var decr = aes.CreateDecryptor())
                {
                    while (cipherText.Count != 0)
                    {
                        if (cipherText.Count == BlockSize)
                        {
                            aes.Padding = PaddingMode.PKCS7;
                        }
                        var block = DetachBlock(cipherText);
                        var decrypted = new byte[BlockSize];
                        decr.TransformBlock(block, 0, BlockSize, decrypted, 0);
                        if (!decrypted.All(x => x == BlockSize))
                        {
                            message.Append(BytesToPlainText(decrypted));
                        }
                        aes.IV = block;
                    }
                }
            }
            return message.ToString();
        }

        private byte[] CompleteBlock(ICollection<byte> block)
        {
            var fullBlock = block.ToList();
            var n = BlockSize - block.Count;
            for (var i = 0; i < n; i++)
            {
                fullBlock.Add((byte) n);
            }
            return fullBlock.ToArray();
        }

        private void AddDummyBlock(ICollection<byte> plainText)
        {
            for (var i = 0; i < BlockSize; i++)
            {
                plainText.Add((byte) BlockSize);
            }
        }
    }
}