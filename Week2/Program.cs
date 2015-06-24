using System;
using System.IO;

namespace Week2
{
    internal static class Program
    {
        private static void Main()
        {
            using (var sr = new StreamReader("..\\..\\cbc.txt"))
            {
                AesAlgorithm cbc = new CbcAes();
                var key = sr.ReadLine();
                string ct;
                while ((ct = sr.ReadLine()) != null)
                {
                    Console.WriteLine(cbc.DecryptMessage(key, ct));
                }
            }

            using (var sr = new StreamReader("..\\..\\ctr.txt"))
            {
                AesAlgorithm ctr = new CtrAes();
                var key = sr.ReadLine();
                string ct;
                while ((ct = sr.ReadLine()) != null)
                {
                    Console.WriteLine(ctr.DecryptMessage(key, ct));
                }
            }
        }
    }
}