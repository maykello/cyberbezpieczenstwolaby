namespace cyberbezpieczenstwolab.Models;

public class PasswordHistory
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public User? User { get; set; }
    public string PasswordHash { get; set; } = string.Empty;
    public string Salt { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
