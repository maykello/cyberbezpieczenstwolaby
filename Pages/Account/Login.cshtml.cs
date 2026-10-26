using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using cyberbezpieczenstwolab.Data;
using cyberbezpieczenstwolab.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace cyberbezpieczenstwolab.Pages.Account;

public class LoginModel : PageModel
{
    private readonly AppDbContext _context;
    private readonly IPasswordService _passwordService;
    private readonly ITotpService _totpService;
    private readonly IAuditService _auditService;

    public LoginModel(
        AppDbContext context,
        IPasswordService passwordService,
        ITotpService totpService,
        IAuditService auditService)
    {
        _context = context;
        _passwordService = passwordService;
        _totpService = totpService;
        _auditService = auditService;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ErrorMessage { get; set; }
    public string? InfoMessage { get; set; }
    public bool RequiresTotp { get; set; }

    public class InputModel
    {
        [Required(ErrorMessage = "Pole Login jest wymagane.")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Pole Haslo jest wymagane.")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        public string? TotpCode { get; set; }
    }

    public async Task OnGetAsync(string? reason, int? timeout)
    {
        if (timeout == 1)
        {
            InfoMessage = "Sesja wygasla z powodu bezczynnosci. Zaloguj sie ponownie.";
            if (User.Identity?.IsAuthenticated == true)
            {
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                HttpContext.Session.Clear();
            }
        }
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        var user = await _context.Users
            .Include(u => u.PasswordHistories)
            .FirstOrDefaultAsync(u => u.Username == Input.Username);

        if (user == null)
        {
            await _auditService.LogAsync(Input.Username, "LOGOWANIE_BLAD", "Nieistniejacy uzytkownik", ip, false);
            ErrorMessage = "Login lub hasło niepoprawne";
            return Page();
        }

        if (!_passwordService.VerifyPassword(Input.Password, user.PasswordHash, user.Salt))
        {
            await _auditService.LogAsync(Input.Username, "LOGOWANIE_BLAD", "Nieprawidlowe haslo", ip, false);
            ErrorMessage = "Login lub hasło niepoprawne";
            return Page();
        }

        if (!user.IsActive)
        {
            await _auditService.LogAsync(Input.Username, "LOGOWANIE_BLAD", "Konto zablokowane", ip, false);
            ErrorMessage = "Login lub hasło niepoprawne";
            return Page();
        }

        if (user.IsTemporaryPassword && user.TemporaryPasswordExpiresAt.HasValue && user.TemporaryPasswordExpiresAt < DateTime.UtcNow)
        {
            await _auditService.LogAsync(Input.Username, "LOGOWANIE_BLAD", "Haslo jednorazowe wygaslo (przekroczony czas waznosci)", ip, false);
            ErrorMessage = "Login lub hasło niepoprawne";
            return Page();
        }

        if (user.IsTotpEnabled)
        {
            if (string.IsNullOrWhiteSpace(Input.TotpCode))
            {
                RequiresTotp = true;
                return Page();
            }

            if (!_totpService.VerifyCode(user.TotpSecret ?? string.Empty, Input.TotpCode))
            {
                await _auditService.LogAsync(Input.Username, "LOGOWANIE_TOTP_BLAD", "Niepoprawny kod jednorazowy TOTP", ip, false);
                ErrorMessage = "Nieprawidlowy kod TOTP.";
                RequiresTotp = true;
                return Page();
            }
        }

        user.LastLoginAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Role, user.Role),
            new("MustChangePassword", user.MustChangePassword ? "true" : "false")
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
        HttpContext.Session.SetString("LastActivityUtc", DateTimeOffset.UtcNow.ToString("o"));

        await _auditService.LogAsync(user.Username, "LOGOWANIE_SUKCES", $"Uwierzytelniono pomyslnie (Rola: {user.Role})", ip, true);

        if (user.MustChangePassword)
        {
            return RedirectToPage("/Account/ForceChangePassword");
        }

        return LocalRedirect(returnUrl);
    }
}
