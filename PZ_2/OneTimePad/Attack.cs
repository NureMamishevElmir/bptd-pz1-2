using System.Text;

namespace OneTimePad;

public record AttackResult(byte[] KeyStream, byte[]? Key, string Plaintext);

// Атака за відомим відкритим текстом (known-plaintext attack).
// Якщо C = P xor K, то K = C xor P: знаючи фрагмент тексту, отримуємо ту саму частину ключа.
// Коли ключ короткий і повторюється, з цього фрагмента відновлюється весь ключ.
public static class Attack
{
    public static byte[] RecoverKeyStream(byte[] cipher, byte[] knownPlain)
    {
        int n = Math.Min(cipher.Length, knownPlain.Length);
        var stream = new byte[n];
        for (int i = 0; i < n; i++)
            stream[i] = (byte)(cipher[i] ^ knownPlain[i]);
        return stream;
    }

    // Шукаємо найкоротший період потоку ключа. Період вважаємо підтвердженим,
    // лише якщо він повторився в потоці хоча б двічі.
    public static byte[]? FindPeriod(byte[] stream)
    {
        for (int p = 1; p <= stream.Length / 2; p++)
        {
            bool repeats = true;
            for (int i = p; i < stream.Length && repeats; i++)
                repeats = stream[i] == stream[i % p];
            if (repeats)
                return stream[..p];
        }
        return null;
    }

    public static AttackResult Run(byte[] cipher, string knownPrefix)
    {
        var stream = RecoverKeyStream(cipher, Encoding.UTF8.GetBytes(knownPrefix));
        var key = FindPeriod(stream);

        if (key != null)
            return new AttackResult(stream, key, Pad.Decrypt(cipher, key));

        // Період не знайдено: розшифрувати можна лише ту частину, для якої відомий ключ.
        var part = Pad.Xor(cipher[..stream.Length], stream);
        return new AttackResult(stream, null, Encoding.UTF8.GetString(part) + " …");
    }
}
