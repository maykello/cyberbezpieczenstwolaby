using cyberbezpieczenstwolab.Data;
using cyberbezpieczenstwolab.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace cyberbezpieczenstwolab.Pages.Admin;

[Authorize(Roles = $"{AppRoles.Administrator},{AppRoles.Audytor}")]
public class AuditModel : PageModel
{
    private readonly AppDbContext _context;

    public AuditModel(AppDbContext context)
    {
        _context = context;
    }

    public List<AuditLog> Logs { get; set; } = [];

    public async Task OnGetAsync()
    {
        Logs = await _context.AuditLogs
            .OrderByDescending(l => l.Timestamp)
            .Take(100)
            .ToListAsync();
    }
}
