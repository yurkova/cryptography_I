using System;
using System.Collections.Generic;
using System.IO;

namespace Week1
{
    internal static class Program
    {
        private static List<List<int>> cipherTexts;
        private static List<List<int>> plainTexts;

        private static void Main()
        {
            var inputCTs = new List<string>();
            using (var sr = new StreamReader(@"..\..\ciphertexts.txt"))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    inputCTs.Add(line);
                }
            }
            ConvertHexStrToIntArr(inputCTs);
            InitializePlainTexts();
            DecryptMessages();
            PrintMessages();
        }

        private static void InitializePlainTexts()
        {
            plainTexts = new List<List<int>>();
            for (var i = 0; i < cipherTexts.Count; i++)
            {
                plainTexts.Add(new List<int>());
                for (var j = 0; j < cipherTexts[i].Count; j++)
                {
                    plainTexts[i].Add('*');
                }
            }
        }

        private static void ConvertHexStrToIntArr(IEnumerable<string> inputCTs)
        {
            cipherTexts = new List<List<int>>();
            foreach (var ct in inputCTs)
            {
                var text = new List<int>();
                for (var j = 0; j < ct.Length; j += 2)
                {
                    text.Add(Convert.ToInt32(ct.Substring(j, 2), 16));
                }
                cipherTexts.Add(text);
            }
        }

        private static void DecryptMessages()
        {
            for (var i = 0; i < cipherTexts.Count; i++)
            {
                for (var j = 0; j < cipherTexts.Count; j++)
                {
                    if (i == j)
                    {
                        continue;
                    }
                    var minLength = Math.Min(cipherTexts[i].Count,
                        cipherTexts[j].Count);
                    for (var k = 0; k < minLength; k++)
                    {
                        var ch = cipherTexts[i][k] ^ cipherTexts[j][k];
                        if (!IsLetter(ch))
                        {
                            continue;
                        }
                        if (!IsSpace(i, k))
                        {
                            continue;
                        }
                        for (var l = 0; l < plainTexts.Count; l++)
                        {
                            if (k >= plainTexts[l].Count
                                || plainTexts[l][k] != '*')
                            {
                                continue;
                            }
                            if (l != i)
                            {
                                plainTexts[l][k] = cipherTexts[l][k]
                                                   ^ cipherTexts[i][k] ^ ' ';
                            }
                            else
                            {
                                plainTexts[l][k] = ' ';
                            }
                        }
                    }
                }
            }
        }

        private static bool IsLetter(int ch)
        {
            return ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'));
        }

        private static bool IsDelimiterOrDigit(int ch)
        {
            var delimiters = new List<int> { ',', '.', ':', ';', '-', '(', ')' };
            var digits = new List<int> {'0', '1', '2', '3', '4', '5', '6', '7',
                                        '8', '9'};
            return (delimiters.Contains(ch ^ ' ') || digits.Contains(ch ^ ' '));
        }

        private static bool IsSpace(int row, int col)
        {
            for (var i = 0; i < cipherTexts.Count; i++)
            {
                if (i == row || col >= cipherTexts[i].Count)
                {
                    continue;
                }
                var ch = cipherTexts[row][col] ^ cipherTexts[i][col];
                if (ch != 0 && !IsLetter(ch) && !IsDelimiterOrDigit(ch))
                {
                    return false;
                }
            }
            return true;
        }

        private static void PrintMessages()
        {
            foreach (var message in plainTexts)
            {
                foreach (var ch in message)
                {
                    Console.Write((char)ch);
                }
                Console.WriteLine();
            }
        }
    }
}