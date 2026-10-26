namespace cyberbezpieczenstwolab.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Salt { get; set; } = string.Empty;
    public string Role { get; set; } = AppRoles.Czytelnik;
    public bool IsActive { get; set; } = true;
    public bool MustChangePassword { get; set; } = false;
    public bool IsTemporaryPassword { get; set; } = false;
    public DateTime? TemporaryPasswordExpiresAt { get; set; }
    public DateTime? PasswordExpiresAt { get; set; }
    public string? TotpSecret { get; set; }
    public bool IsTotpEnabled { get; set; } = false;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }

    public List<PasswordHistory> PasswordHistories { get; set; } = [];
}
