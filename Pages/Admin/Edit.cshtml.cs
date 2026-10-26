using System.ComponentModel.DataAnnotations;
using cyberbezpieczenstwolab.Data;
using cyberbezpieczenstwolab.Models;
using cyberbezpieczenstwolab.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace cyberbezpieczenstwolab.Pages.Admin;

[Authorize(Roles = $"{AppRoles.Administrator},{AppRoles.Audytor}")]
public class EditModel : PageModel
{
    private readonly AppDbContext _context;
    private readonly IAuditService _auditService;

    public EditModel(AppDbContext context, IAuditService auditService)
    {
        _context = context;
        _auditService = auditService;
    }

    public bool IsReadOnly { get; set; }
    public string? ErrorMessage { get; set; }

    [BindProperty]
    public EditUserInput Input { get; set; } = new();

    public class EditUserInput
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Login jest wymagany.")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Login musi miec od 3 do 50 znakow.")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Wybierz role.")]
        public string Role { get; set; } = AppRoles.Czytelnik;

        public bool IsActive { get; set; }

        public bool MustChangePassword { get; set; }
    }

    public async Task<IActionResult> OnGetAsync(int id)
    {
        IsReadOnly = !User.IsInRole(AppRoles.Administrator);

        var user = await _context.Users.FindAsync(id);
        if (user == null)
        {
            return RedirectToPage("/Admin/Index");
        }

        Input = new EditUserInput
        {
            Id = user.Id,
            Username = user.Username,
            Role = user.Role,
            IsActive = user.IsActive,
            MustChangePassword = user.MustChangePassword
        };

        return Page();
    }

    public async Task<IActionResult> OnPostAsync(int id)
    {
        if (!User.IsInRole(AppRoles.Administrator))
        {
            var ipForbidden = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
            await _auditService.LogAsync(User.Identity?.Name, "AUDYTOR_PROBA_MODYFIKACJI_403", "Audytor probowal edytowac uzytkownika.", ipForbidden, false);
            return Forbid();
        }

        if (!ModelState.IsValid)
        {
            IsReadOnly = false;
            return Page();
        }

        var user = await _context.Users.FindAsync(id);
        if (user == null)
        {
            return RedirectToPage("/Admin/Index");
        }

        bool usernameTaken = await _context.Users.AnyAsync(u => u.Id != id && u.Username.ToLower() == Input.Username.ToLower());
        if (usernameTaken)
        {
            ErrorMessage = "Podany login jest juz zajety przez innego uzytkownika.";
            IsReadOnly = false;
            return Page();
        }

        string oldValues = $"Username: {user.Username}, Role: {user.Role}, Active: {user.IsActive}";

        user.Username = Input.Username;
        user.Role = Input.Role;
        user.IsActive = Input.IsActive;
        user.MustChangePassword = Input.MustChangePassword;

        await _context.SaveChangesAsync();

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        await _auditService.LogAsync(User.Identity?.Name, "EDYCJA_UZYTKOWNIKA", $"Zaktualizowano uzytkownika ID={user.Id}. Poprzednie: [{oldValues}], Nowe: [Username: {user.Username}, Role: {user.Role}, Active: {user.IsActive}]", ip, true);

        TempData["SuccessMessage"] = $"Zaktualizowano dane uzytkownika '{user.Username}'.";
        return RedirectToPage("/Admin/Index");
    }
}
