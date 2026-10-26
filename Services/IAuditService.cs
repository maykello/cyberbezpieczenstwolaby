namespace cyberbezpieczenstwolab.Services;

public interface IAuditService
{
    Task LogAsync(string? username, string action, string details, string? ipAddress = null, bool isSuccess = true);
}
