using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Week2
{
    internal class CtrAes : AesAlgorithm
    {
        protected override string EncryptByBlocks(byte[] key,
            List<byte> plainText)
        {
            var cipherText = new StringBuilder();
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.GenerateIV();
                cipherText.Append(BytesToHexString(aes.IV));
                while (plainText.Count != 0)
                {
                    var block = DetachBlock(plainText);
                    var encryptedBlock = EncryptBlock(key, aes.IV, block);
                    cipherText.Append(BytesToHexString(encryptedBlock));
                    aes.IV = IncrementIV(aes.IV);
                }
            }
            return cipherText.ToString();
        }


        protected override string DecryptByBlocks(byte[] key, byte[] iv,
            List<byte> cipherText)
        {
            var message = new StringBuilder();
            while (cipherText.Count != 0)
            {
                var block = DetachBlock(cipherText);
                var decryptedBlock = EncryptBlock(key, iv, block);
                message.Append(BytesToPlainText(decryptedBlock));
                IncrementIV(iv);
            }
            return message.ToString();
        }

        private IEnumerable<byte> EncryptBlock(byte[] key, byte[] iv,
            IList<byte> block)
        {
            var encryptedBlock = new byte[block.Count];
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = KeySize * 8;
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using (var encr = aes.CreateEncryptor())
                {
                    var encryptedIV = new byte[aes.IV.Length];
                    encr.TransformBlock(aes.IV, 0, aes.IV.Length, encryptedIV, 0);
                    for (var i = 0; i < block.Count; i++)
                    {
                        encryptedBlock[i] = (byte) (block[i] ^ encryptedIV[i]);
                    }
                }
            }
            return encryptedBlock;
        }

        private static byte[] IncrementIV(byte[] iv)
        {
            if (iv == null)
            {
                throw new ArgumentNullException("iv");
            }
            for (var i = iv.Length - 1; i >= 0; i--)
            {
                if (iv[i] < 255)
                {
                    iv[i]++;
                    return iv;
                }
                iv[i] = 0;
                if (i == 0)
                {
                    iv[iv.Length - 1] = 1;
                }
            }
            return iv;
        }
    }
}