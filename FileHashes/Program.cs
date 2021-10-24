using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace FileHashes
{
    class Program
    {

        static void Main(string[] args)
        {
            Console.WriteLine("Creating hashes...");
            List<string> hs = new();

            long datHashLastBytes = 100000000; // 100MB

            DirectoryInfo d = new DirectoryInfo(Path.GetDirectoryName(Process.GetCurrentProcess().MainModule?.FileName));

            FileInfo[] Files = d.GetFiles("*.*", SearchOption.AllDirectories);

            foreach (FileInfo file in Files)
            {
                MD5 md5 = MD5.Create();
                string hash = "";

                string folder = file.DirectoryName;

                if (!folder.Contains("\\bin") && file.Length > datHashLastBytes)
                {
                    long datLength = file.Length;

                    byte[] dat = new byte[datHashLastBytes];
                    using (BinaryReader reader = new BinaryReader(new FileStream(file.FullName, FileMode.Open)))
                    {
                        reader.BaseStream.Seek(datLength - datHashLastBytes, SeekOrigin.Begin);
                        reader.Read(dat, 0, (int)datHashLastBytes);

                        reader.Close();
                    }
                    byte[] datHashBytes = md5.ComputeHash(dat);
                    hash = datHashBytes.ByteArrayToHexViaLookup32().ToUpperInvariant();
                }
                else
                {
                    hash = md5.ComputeHash(File.ReadAllBytes(file.FullName)).ByteArrayToHexViaLookup32().ToUpperInvariant();
                }

                hs.Add(file.FullName + " " + hash);
            }

            File.WriteAllLines("FileHashes.list", hs.ToArray());
            Console.WriteLine("Hashes created.");
            Console.ReadKey();
        }
    }

    public static class StringExtensions
    {
        private static readonly uint[] _lookup32 = CreateLookup32();

        private static uint[] CreateLookup32()
        {
            var result = new uint[256];
            for (int i = 0; i < 256; i++)
            {
                string s = i.ToString("X2");
                result[i] = ((uint)s[0]) + ((uint)s[1] << 16);
            }
            return result;
        }

        public static string ByteArrayToHexViaLookup32(this byte[] bytes)
        {
            var lookup32 = _lookup32;
            var result = new char[bytes.Length * 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                var val = lookup32[bytes[i]];
                result[2 * i] = (char)val;
                result[2 * i + 1] = (char)(val >> 16);
            }
            return new string(result);
        }
    }
}