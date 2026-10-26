using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using cyberbezpieczenstwolab.Models;
using Konscious.Security.Cryptography;

namespace cyberbezpieczenstwolab.Services;

public class PasswordService : IPasswordService
{
    private const string SafeOtpAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private const int MemorySizeKb = 32768;
    private const int Iterations = 4;
    private const int DegreeOfParallelism = 2;
    private const int SaltSize = 16;
    private const int HashSize = 32;

    public (string Hash, string Salt) HashPassword(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] hash = ComputeArgon2Id(password, salt);

        return (Convert.ToBase64String(hash), Convert.ToBase64String(salt));
    }

    public bool VerifyPassword(string password, string storedHash, string storedSalt)
    {
        try
        {
            byte[] salt = Convert.FromBase64String(storedSalt);
            byte[] expectedHash = Convert.FromBase64String(storedHash);
            byte[] actualHash = ComputeArgon2Id(password, salt);

            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }
        catch
        {
            return false;
        }
    }

    public string GenerateOneTimePassword()
    {
        char[] chars = new char[12];
        for (int i = 0; i < chars.Length; i++)
        {
            int index = RandomNumberGenerator.GetInt32(SafeOtpAlphabet.Length);
            chars[i] = SafeOtpAlphabet[index];
        }

        return new string(chars);
    }

    public (bool IsValid, string? ErrorMessage) ValidatePasswordPolicy(string password, SecurityPolicy policy, User? user = null)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return (false, "Haslo nie moze byc puste.");
        }

        if (password.Length < policy.MinPasswordLength)
        {
            return (false, $"Haslo musi miec co najmniej {policy.MinPasswordLength} znakow.");
        }

        if (policy.EnableDateAndYearRestriction)
        {
            if (ContainsYearBetween1950And2030(password))
            {
                return (false, "Polityka bezpieczenstwa: haslo nie moze zawierac roku z zakresu 1950-2030.");
            }

            if (ContainsDateFormat(password))
            {
                return (false, "Polityka bezpieczenstwa: haslo nie moze miec postaci ani zawierac formatu daty.");
            }
        }

        if (user != null)
        {
            if (!string.IsNullOrEmpty(user.PasswordHash) && !string.IsNullOrEmpty(user.Salt))
            {
                if (VerifyPassword(password, user.PasswordHash, user.Salt))
                {
                    return (false, "Nowe haslo nie moze byc takie samo jak biezace haslo.");
                }
            }

            if (user.PasswordHistories != null)
            {
                foreach (var history in user.PasswordHistories)
                {
                    if (VerifyPassword(password, history.PasswordHash, history.Salt))
                    {
                        return (false, "Nowe haslo nie moze powtarzac zadnego z poprzednio uzywanych hasel.");
                    }
                }
            }
        }

        return (true, null);
    }

    private static byte[] ComputeArgon2Id(string password, byte[] salt)
    {
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = DegreeOfParallelism,
            MemorySize = MemorySizeKb,
            Iterations = Iterations
        };

        return argon2.GetBytes(HashSize);
    }

    private static bool ContainsYearBetween1950And2030(string input)
    {
        var match = Regex.Match(input, @"(19[5-9]\d|20[0-2]\d|2030)");
        return match.Success;
    }

    private static bool ContainsDateFormat(string input)
    {
        if (Regex.IsMatch(input, @"\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b"))
        {
            return true;
        }

        if (Regex.IsMatch(input, @"\b\d{4}[./-]\d{1,2}[./-]\d{1,2}\b"))
        {
            return true;
        }

        var digitMatches = Regex.Matches(input, @"\d{8}");
        foreach (Match m in digitMatches)
        {
            string s = m.Value;
            string[] formats = ["ddMMyyyy", "yyyyMMdd", "MMddyyyy"];
            if (DateTime.TryParseExact(s, formats, CultureInfo.InvariantCulture, DateTimeStyles.None, out _))
            {
                return true;
            }
        }

        return false;
    }
}
