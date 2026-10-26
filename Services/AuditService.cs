using cyberbezpieczenstwolab.Data;
using cyberbezpieczenstwolab.Models;

namespace cyberbezpieczenstwolab.Services;

public class AuditService : IAuditService
{
    private readonly AppDbContext _context;

    public AuditService(AppDbContext context)
    {
        _context = context;
    }

    public async Task LogAsync(string? username, string action, string details, string? ipAddress = null, bool isSuccess = true)
    {
        var log = new AuditLog
        {
            Timestamp = DateTime.UtcNow,
            Username = string.IsNullOrWhiteSpace(username) ? "ANONIM" : username,
            Action = action,
            Details = details,
            IpAddress = string.IsNullOrWhiteSpace(ipAddress) ? "127.0.0.1" : ipAddress,
            IsSuccess = isSuccess
        };

        _context.AuditLogs.Add(log);
        await _context.SaveChangesAsync();
    }
}
