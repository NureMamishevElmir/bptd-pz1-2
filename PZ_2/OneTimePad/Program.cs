using System.Text;
using OneTimePad;

Console.InputEncoding = Encoding.UTF8;
Console.OutputEncoding = Encoding.UTF8;

while (true)
{
    Console.WriteLine();
    Console.WriteLine("=== Одноразовий блокнот (XOR) ===");
    Console.WriteLine("1 – Зашифрувати");
    Console.WriteLine("2 – Розшифрувати");
    Console.WriteLine("3 – Атака за відомим фрагментом тексту");
    Console.WriteLine("4 – Демонстрація");
    Console.WriteLine("0 – Вихід");
    Console.Write("Вибір: ");

    try
    {
        switch (Console.ReadLine()?.Trim())
        {
            case "1": EncryptMenu(); break;
            case "2": DecryptMenu(); break;
            case "3": AttackMenu(); break;
            case "4": Demo(); break;
            case "0": return;
            default: Console.WriteLine("Невідомий пункт меню."); break;
        }
    }
    catch (FormatException)
    {
        Console.WriteLine("Помилка: шифротекст і hex-ключ мають складатися з шістнадцяткових цифр.");
    }
    catch (ArgumentException e)
    {
        Console.WriteLine("Помилка: " + e.Message);
    }
}

static string Ask(string prompt)
{
    Console.Write(prompt);
    return Console.ReadLine() ?? "";
}

// Ключ вводиться словом (повторюється циклічно, як у ПЗ1) або в hex з префіксом "hex:".
static byte[] ParseKey(string input) =>
    input.StartsWith("hex:", StringComparison.OrdinalIgnoreCase)
        ? Convert.FromHexString(input[4..].Trim())
        : Encoding.UTF8.GetBytes(input);

static void EncryptMenu()
{
    string text = Ask("Відкритий текст: ");
    string keyInput = Ask("Ключ-слово (Enter – випадковий одноразовий ключ): ");

    byte[] key = keyInput.Length == 0
        ? Pad.GenerateKey(Encoding.UTF8.GetByteCount(text))
        : ParseKey(keyInput);

    byte[] cipher = Pad.Encrypt(text, key);
    Console.WriteLine("Шифротекст (hex): " + Convert.ToHexString(cipher));
    if (keyInput.Length == 0)
        Console.WriteLine("Ключ (hex):       " + Convert.ToHexString(key));
}

static void DecryptMenu()
{
    byte[] cipher = Convert.FromHexString(Ask("Шифротекст (hex): ").Trim());
    byte[] key = ParseKey(Ask("Ключ (слово або hex:...): "));
    Console.WriteLine("Відкритий текст: " + Pad.Decrypt(cipher, key));
}

static void AttackMenu()
{
    byte[] cipher = Convert.FromHexString(Ask("Перехоплений шифротекст (hex): ").Trim());
    string known = Ask("Відомий початок тексту: ");
    PrintAttack(Attack.Run(cipher, known));
}

static void PrintAttack(AttackResult r)
{
    Console.WriteLine("Відновлений потік ключа: " + Convert.ToHexString(r.KeyStream));
    if (r.Key != null)
    {
        Console.WriteLine($"Період ключа: {r.Key.Length} байт");
        Console.WriteLine("Ключ (hex): " + Convert.ToHexString(r.Key));
        Console.WriteLine("Ключ (текст): " + Encoding.UTF8.GetString(r.Key));
    }
    else
    {
        Console.WriteLine("Період не знайдено: ключ не повторюється або відомий фрагмент коротший " +
                          "за дві довжини ключа. Відновлено лише ту частину, для якої відомий ключ.");
    }
    Console.WriteLine("Результат атаки: " + r.Plaintext);
}

static void Demo()
{
    const string text = "Асиметрична криптографія стала елегантним розв'язанням задачі розподілу ключів.";
    const string known = "Асиметрична криптографія";

    Console.WriteLine("Відкритий текст: " + text);
    Console.WriteLine("Атакувальнику відомо лише початок: " + known);

    Console.WriteLine();
    Console.WriteLine("--- Випадок 1: короткий ключ «ключ», що повторюється ---");
    byte[] weak = Pad.Encrypt(text, Encoding.UTF8.GetBytes("ключ"));
    Console.WriteLine("Шифротекст (hex): " + Convert.ToHexString(weak));
    PrintAttack(Attack.Run(weak, known));

    Console.WriteLine();
    Console.WriteLine("--- Випадок 2: справжній одноразовий ключ (випадковий, завдовжки з текст) ---");
    byte[] otpKey = Pad.GenerateKey(Encoding.UTF8.GetByteCount(text));
    byte[] strong = Pad.Encrypt(text, otpKey);
    Console.WriteLine("Шифротекст (hex): " + Convert.ToHexString(strong));
    PrintAttack(Attack.Run(strong, known));
    Console.WriteLine("Перевірка законного одержувача: " + Pad.Decrypt(strong, otpKey));
}
