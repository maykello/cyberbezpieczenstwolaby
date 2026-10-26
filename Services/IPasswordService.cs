using cyberbezpieczenstwolab.Models;

namespace cyberbezpieczenstwolab.Services;

public interface IPasswordService
{
    (string Hash, string Salt) HashPassword(string password);
    bool VerifyPassword(string password, string storedHash, string storedSalt);
    string GenerateOneTimePassword();
    (bool IsValid, string? ErrorMessage) ValidatePasswordPolicy(string password, SecurityPolicy policy, User? user = null);
}
