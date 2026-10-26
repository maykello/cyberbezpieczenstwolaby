using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using cyberbezpieczenstwolab.Data;
using cyberbezpieczenstwolab.Models;
using cyberbezpieczenstwolab.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace cyberbezpieczenstwolab.Pages.Account;

public class ForceChangePasswordModel : PageModel
{
    private readonly AppDbContext _context;
    private readonly IPasswordService _passwordService;
    private readonly IAuditService _auditService;

    public ForceChangePasswordModel(
        AppDbContext context,
        IPasswordService passwordService,
        IAuditService auditService)
    {
        _context = context;
        _passwordService = passwordService;
        _auditService = auditService;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ErrorMessage { get; set; }
    public int MinLength { get; set; } = 15;
    public bool HasDateRestriction { get; set; } = true;

    public class InputModel
    {
        [Required(ErrorMessage = "Nowe haslo jest wymagane.")]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Powtorzenie nowego hasla jest wymagane.")]
        [DataType(DataType.Password)]
        [Compare("NewPassword", ErrorMessage = "Wprowadzone hasla nie sa identyczne.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        var policy = await _context.SecurityPolicies.AsNoTracking().FirstOrDefaultAsync();
        if (policy != null)
        {
            MinLength = policy.MinPasswordLength;
            HasDateRestriction = policy.EnableDateAndYearRestriction;
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var username = User.Identity?.Name;
        if (string.IsNullOrEmpty(username))
        {
            return RedirectToPage("/Account/Login");
        }

        var policy = await _context.SecurityPolicies.FirstOrDefaultAsync();
        if (policy != null)
        {
            MinLength = policy.MinPasswordLength;
            HasDateRestriction = policy.EnableDateAndYearRestriction;
        }

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _context.Users
            .Include(u => u.PasswordHistories)
            .FirstOrDefaultAsync(u => u.Username == username);

        if (user == null)
        {
            return RedirectToPage("/Account/Login");
        }

        var validationResult = _passwordService.ValidatePasswordPolicy(Input.NewPassword, policy ?? new(), user);
        if (!validationResult.IsValid)
        {
            ErrorMessage = validationResult.ErrorMessage;
            return Page();
        }

        var (newHash, newSalt) = _passwordService.HashPassword(Input.NewPassword);

        user.PasswordHash = newHash;
        user.Salt = newSalt;
        user.MustChangePassword = false;
        user.IsTemporaryPassword = false;
        user.TemporaryPasswordExpiresAt = null;
        user.PasswordExpiresAt = DateTime.UtcNow.AddDays(policy?.PasswordValidityDays ?? 90);

        _context.PasswordHistories.Add(new PasswordHistory
        {
            UserId = user.Id,
            PasswordHash = newHash,
            Salt = newSalt,
            CreatedAt = DateTime.UtcNow
        });

        await _context.SaveChangesAsync();

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Role, user.Role),
            new("MustChangePassword", "false")
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        await _auditService.LogAsync(username, "WYMUSZONA_ZMIANA_HASLA_SUKCES", "Haslo zmienione przy pierwszym logowaniu.", ip, true);

        TempData["SuccessMessage"] = "Haslo zostalo pomyslnie zmienione. Mozesz korzystac z systemu.";
        return RedirectToPage("/Index");
    }
}
