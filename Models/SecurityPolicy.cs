namespace cyberbezpieczenstwolab.Models;

public class SecurityPolicy
{
    public int Id { get; set; }
    public int MinPasswordLength { get; set; } = 15;
    public bool EnableDateAndYearRestriction { get; set; } = true;
    public int PasswordValidityDays { get; set; } = 90;
    public int SessionIdleTimeoutMinutes { get; set; } = 15;
    public int TemporaryPasswordValidityHours { get; set; } = 24;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
