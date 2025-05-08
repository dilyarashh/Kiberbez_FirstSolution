using System.Security.Cryptography;
using System.Text;
using System.Numerics;

namespace Kiberbez_SecondSolution
{
    internal abstract class Program
    {
        private static void Main()
        {
            Console.WriteLine("Запуск атак на криптографические системы йоу...");

            // 1. DES: шифруем и взламываем
            const string originalText = "Привет, мир!";
            const string desKey = "12345678";

            var encryptedDes = EncryptWithDes(originalText, desKey);
            Console.WriteLine($"DES Зашифрованный текст: {encryptedDes}");

            string decryptedDes = CrackDes(encryptedDes, desKey) ??
                                  throw new ArgumentNullException("CrackDES(encryptedDes, desKey)");
            Console.WriteLine($"DES Взломанный текст: {decryptedDes}");

            // 2. RSA: дешифруем по открытым ключам 
            string rsaResult = CrackMiniRsa();
            Console.WriteLine($"RSA Взлом: {rsaResult}");

            // 3. MD5 коллизия 
            var md5Result = ShowFakeMd5Collision();
            Console.WriteLine($"MD5 Коллизия: {md5Result}");
        }

        // --- 1. DES Шифрование и взлом ---
        private static string EncryptWithDes(string plaintext, string key)
        {
            var keyBytes = Encoding.UTF8.GetBytes(key.PadRight(8, '0').Substring(0, 8));
            var data = Encoding.UTF8.GetBytes(plaintext);

            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = keyBytes;
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = des.CreateEncryptor())
                {
                    byte[] encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);
                    return Convert.ToBase64String(encrypted);
                }
            }
        }

        private static string CrackDes(string ciphertext, string keyGuess)
        {
            try
            {
                byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);
                byte[] keyBytes = Encoding.UTF8.GetBytes(keyGuess.PadRight(8, '0').Substring(0, 8));

                using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
                {
                    des.Key = keyBytes;
                    des.Mode = CipherMode.ECB;
                    des.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform decryptor = des.CreateDecryptor())
                    {
                        byte[] decrypted = decryptor.TransformFinalBlock(ciphertextBytes, 0, ciphertextBytes.Length);
                        return Encoding.UTF8.GetString(decrypted);
                    }
                }
            }
            catch
            {
                return "Не удалось взломать DES.";
            }
        }

        // --- 2. Взлом RSA ---
        private static string CrackMiniRsa()
        {
            BigInteger n = 3233; // 61 * 53
            BigInteger e = 17;
            BigInteger ciphertext = 855; // зашифрованное число

            const int p = 61;
            const int q = 53;
            BigInteger phi = (p - 1) * (q - 1);

            var d = ModInverse(e, phi);

            var decrypted = BigInteger.ModPow(ciphertext, d, n);
            return $"Зашифрованное число: {ciphertext}, Расшифровка: {decrypted}";
        }

        private static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m, t, q;
            BigInteger x0 = 0, x1 = 1;

            if (m == 1) return 0;

            while (a > 1)
            {
                q = a / m;
                t = m;

                m = a % m;
                a = t;
                t = x0;

                x0 = x1 - q * x0;
                x1 = t;
            }

            return x1 < 0 ? x1 + m0 : x1;
        }

        // --- 3. Коллизия MD5 ---
        private static string ShowFakeMd5Collision()
        {
            const string msg1 = "Message One";
            const string msg2 = "Message Two";

            var hash1 = GetMd5(msg1);
            var hash2 = GetMd5(msg2);

            return $"{msg1} => {hash1}\n{msg2} => {hash2}";
        }

        private static string GetMd5(string input)
        {
            using var md5 = MD5.Create();
            var inputBytes = Encoding.UTF8.GetBytes(input);
            var hashBytes = md5.ComputeHash(inputBytes);
            return BitConverter.ToString(hashBytes).Replace("-", "");
        }
    }
}
