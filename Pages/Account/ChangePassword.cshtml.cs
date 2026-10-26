using System.ComponentModel.DataAnnotations;
using cyberbezpieczenstwolab.Data;
using cyberbezpieczenstwolab.Models;
using cyberbezpieczenstwolab.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace cyberbezpieczenstwolab.Pages.Account;

public class ChangePasswordModel : PageModel
{
    private readonly AppDbContext _context;
    private readonly IPasswordService _passwordService;
    private readonly IAuditService _auditService;

    public ChangePasswordModel(
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
    public string? SuccessMessage { get; set; }
    public int MinLength { get; set; } = 15;
    public bool HasDateRestriction { get; set; } = true;

    public class InputModel
    {
        [Required(ErrorMessage = "Dotychczasowe haslo jest wymagane.")]
        [DataType(DataType.Password)]
        public string OldPassword { get; set; } = string.Empty;

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

        if (!_passwordService.VerifyPassword(Input.OldPassword, user.PasswordHash, user.Salt))
        {
            var ipErr = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
            await _auditService.LogAsync(username, "ZMIANA_HASLA_BLAD", "Bledne dotychczasowe haslo.", ipErr, false);
            ErrorMessage = "Dotychczasowe haslo jest niepoprawne.";
            return Page();
        }

        var validation = _passwordService.ValidatePasswordPolicy(Input.NewPassword, policy ?? new(), user);
        if (!validation.IsValid)
        {
            ErrorMessage = validation.ErrorMessage;
            return Page();
        }

        var (newHash, newSalt) = _passwordService.HashPassword(Input.NewPassword);

        user.PasswordHash = newHash;
        user.Salt = newSalt;
        user.PasswordExpiresAt = DateTime.UtcNow.AddDays(policy?.PasswordValidityDays ?? 90);

        _context.PasswordHistories.Add(new PasswordHistory
        {
            UserId = user.Id,
            PasswordHash = newHash,
            Salt = newSalt,
            CreatedAt = DateTime.UtcNow
        });

        await _context.SaveChangesAsync();

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        await _auditService.LogAsync(username, "ZMIANA_HASLA_SUKCES", "Haslo zmienione poprawnie przez uzytkownika.", ip, true);

        SuccessMessage = "Haslo zostalo pomyslnie zmienione.";
        ModelState.Clear();
        Input = new InputModel();

        return Page();
    }
}
