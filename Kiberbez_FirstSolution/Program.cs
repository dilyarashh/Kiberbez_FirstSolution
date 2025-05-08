using System.Security.Cryptography;
using System.Text;

namespace Kiberbez_FirstSolution;

public abstract class SecureTunnel
{
    public static void Main()
    {
        // Создание двух сторон, использующих ECC для обмена ключами
        using var alice = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        // Получаем публичные ключи
        var alicePubKey = alice.PublicKey;
        var bobPubKey = bob.PublicKey;

        // Генерация общего секрета на основе публичных ключей
        byte[] aliceKey = alice.DeriveKeyMaterial(bobPubKey);
        byte[] bobKey = bob.DeriveKeyMaterial(alicePubKey);

        Console.WriteLine("Общий ключ совпадает: " + aliceKey.SequenceEqual(bobKey));

        // Шифруем сообщение с использованием симметричного ключа
        string message = "Я уже хочу спать боже помоги";
        byte[] encryptedMessage = EncryptMessageWithAes(aliceKey, message);
        Console.WriteLine("Зашифрованное сообщение: " + Convert.ToBase64String(encryptedMessage));

        // Дешифровка на стороне Bob с использованием его ключа
        string decryptedMessage = DecryptMessageWithAes(bobKey, encryptedMessage);
        Console.WriteLine("Расшифрованное сообщение: " + decryptedMessage);
    }

    // Шифрование симметричного ключа с помощью AES
    private static byte[] EncryptMessageWithAes(byte[] key, string message)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.GenerateIV(); // Генерация случайного IV
            byte[] iv = aes.IV;

            using (var encryptor = aes.CreateEncryptor())
            {
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                byte[] encryptedMessage = encryptor.TransformFinalBlock(messageBytes, 0, messageBytes.Length);

                // Комбинируем IV и зашифрованное сообщение для передачи
                byte[] result = new byte[iv.Length + encryptedMessage.Length];
                Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                Buffer.BlockCopy(encryptedMessage, 0, result, iv.Length, encryptedMessage.Length);

                return result;
            }
        }
    }

    // Дешифровка сообщения с помощью AES
    private static string DecryptMessageWithAes(byte[] key, byte[] encryptedMessage)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = key;

            // Извлекаем IV из первых 16 байт (для AES)
            byte[] iv = encryptedMessage.Take(16).ToArray();
            aes.IV = iv;

            // Извлекаем зашифрованную часть
            byte[] cipherText = encryptedMessage.Skip(16).ToArray();

            using (var decryptor = aes.CreateDecryptor())
            {
                byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }
    }
}