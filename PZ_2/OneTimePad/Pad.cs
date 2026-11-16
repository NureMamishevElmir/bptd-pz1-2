using System.Security.Cryptography;
using System.Text;

namespace OneTimePad;

// Шифр «одноразовий блокнот» у машинному варіанті:
// текст кодується в байти UTF-8, замість додавання за модулем 10 – XOR.
public static class Pad
{
    // XOR кожного байта даних з байтом ключа. Короткий ключ повторюється циклічно.
    // Операція оборотна: (P xor K) xor K = P, тому вона ж і дешифрує.
    public static byte[] Xor(byte[] data, byte[] key)
    {
        if (key.Length == 0)
            throw new ArgumentException("Ключ не може бути порожнім.");

        var result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        return result;
    }

    // Справжній одноразовий ключ: випадкові байти завдовжки з повідомлення.
    public static byte[] GenerateKey(int length) => RandomNumberGenerator.GetBytes(length);

    public static byte[] Encrypt(string text, byte[] key) => Xor(Encoding.UTF8.GetBytes(text), key);

    public static string Decrypt(byte[] cipher, byte[] key) => Encoding.UTF8.GetString(Xor(cipher, key));
}
