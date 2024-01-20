using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class FileEncryption
{
    public static string password = "SecretKey";

    public static void Main()
    {
        string inputFile = "test.txt";
        string encryptedFile = "test.txt.encrypted";

        // // // Encrypt File
         EncryptFile(inputFile, encryptedFile, password);

        string decryptedFile = "test.txt";

        // // // Decrypt file
        // DecryptFile(encryptedFile, inputFile, password);
    }

    public static void EncryptFile(string inputFile, string outputFile, string password)
    {
        try
        {
            var keyDerivationFunction = new Rfc2898DeriveBytes(password, new byte[] { 0x49, 0x76, 0x61, 0x6E, 0x20, 0x4D, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
            var key = keyDerivationFunction.GetBytes(32);

            using (var aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = key;
                var fileSize = new FileInfo(inputFile).Length;

                using (var msInput = new MemoryStream())
                {
                    using (var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                    {
                        fsInput.CopyTo(msInput);
                    }

                    var iv = new byte[] { 0x5C, 0xD2, 0x23, 0x95, 0xEE, 0xEF, 0x2A, 0x45, 0x25, 0x47, 0xAA, 0x47, 0x3A, 0xEC, 0x45, 0xEA };
                    aesAlg.IV = iv;

                    using (var fsEncrypted = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                    {
                        fsEncrypted.Write(iv, 0, iv.Length);

                        using (var csEncrypt = new CryptoStream(fsEncrypted, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            msInput.Seek(0, SeekOrigin.Begin);
                            msInput.CopyTo(csEncrypt);
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }

    public static void DecryptFile(string inputFile, string outputFile, string password)
    {
        try
        {
            var keyDerivationFunction = new Rfc2898DeriveBytes(password, new byte[] { 0x49, 0x76, 0x61, 0x6E, 0x20, 0x4D, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
            var key = keyDerivationFunction.GetBytes(32);

            using (var aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = key;

                using (var msOutput = new MemoryStream())
                {
                    var iv = new byte[] { 0x5C, 0xD2, 0x23, 0x95, 0xEE, 0xEF, 0x2A, 0x45, 0x25, 0x47, 0xAA, 0x47, 0x3A, 0xEC, 0x45, 0xEA };
                    aesAlg.IV = iv;

                    using (var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                    {
                        fsInput.Read(iv, 0, iv.Length);
                        aesAlg.IV = iv;
                    }

                    using (var csDecrypt = new CryptoStream(msOutput, aesAlg.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        using (var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                        {
                            fsInput.Seek(16, SeekOrigin.Begin);
                            fsInput.CopyTo(csDecrypt);
                        }
                    }

                    using (var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                    {
                        msOutput.Seek(0, SeekOrigin.Begin);
                        msOutput.CopyTo(fsOutput);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }
}
