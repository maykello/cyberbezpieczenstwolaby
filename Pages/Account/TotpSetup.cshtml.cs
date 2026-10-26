using System.ComponentModel.DataAnnotations;
using cyberbezpieczenstwolab.Data;
using cyberbezpieczenstwolab.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace cyberbezpieczenstwolab.Pages.Account;

public class TotpSetupModel : PageModel
{
    private readonly AppDbContext _context;
    private readonly ITotpService _totpService;
    private readonly IAuditService _auditService;

    public TotpSetupModel(
        AppDbContext context,
        ITotpService totpService,
        IAuditService auditService)
    {
        _context = context;
        _totpService = totpService;
        _auditService = auditService;
    }

    public bool IsTotpEnabled { get; set; }
    public string? SecretKey { get; set; }
    public string? QrCodeImageBase64 { get; set; }
    public string? ErrorMessage { get; set; }
    public string? SuccessMessage { get; set; }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public class InputModel
    {
        [Required(ErrorMessage = "Podaj 6-cyfrowy kod weryfikacyjny.")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Kod musi miec dokladnie 6 cyfr.")]
        public string Code { get; set; } = string.Empty;

        public string SecretKey { get; set; } = string.Empty;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        var username = User.Identity?.Name;
        if (string.IsNullOrEmpty(username))
        {
            return RedirectToPage("/Account/Login");
        }

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null)
        {
            return RedirectToPage("/Account/Login");
        }

        IsTotpEnabled = user.IsTotpEnabled;

        if (!IsTotpEnabled)
        {
            SecretKey = _totpService.GenerateSecretKey();
            var uri = _totpService.GenerateQrCodeUri(user.Username, SecretKey);
            QrCodeImageBase64 = _totpService.GenerateQrCodeBase64Image(uri);
            Input.SecretKey = SecretKey;
        }

        return Page();
    }

    public async Task<IActionResult> OnPostEnableAsync()
    {
        var username = User.Identity?.Name;
        if (string.IsNullOrEmpty(username))
        {
            return RedirectToPage("/Account/Login");
        }

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null)
        {
            return RedirectToPage("/Account/Login");
        }

        if (string.IsNullOrWhiteSpace(Input.SecretKey) || string.IsNullOrWhiteSpace(Input.Code))
        {
            ErrorMessage = "Nieprawidlowe dane formularza.";
            return await OnGetAsync();
        }

        bool isValid = _totpService.VerifyCode(Input.SecretKey, Input.Code);
        if (!isValid)
        {
            ErrorMessage = "Podany kod jest niepoprawny lub wygasl. Sprobuj ponownie.";
            SecretKey = Input.SecretKey;
            var uri = _totpService.GenerateQrCodeUri(user.Username, SecretKey);
            QrCodeImageBase64 = _totpService.GenerateQrCodeBase64Image(uri);
            return Page();
        }

        user.TotpSecret = Input.SecretKey;
        user.IsTotpEnabled = true;
        await _context.SaveChangesAsync();

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        await _auditService.LogAsync(username, "TOTP_WLACZONE", "Uzytkownik wlaczyl dwuskladnikowe uwierzytelnianie TOTP.", ip, true);

        SuccessMessage = "Uwierzytelnianie dwuskladnikowe TOTP zostalo pomyslnie aktywowane.";
        IsTotpEnabled = true;
        return Page();
    }

    public async Task<IActionResult> OnPostDisableAsync()
    {
        var username = User.Identity?.Name;
        if (string.IsNullOrEmpty(username))
        {
            return RedirectToPage("/Account/Login");
        }

        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user == null)
        {
            return RedirectToPage("/Account/Login");
        }

        user.TotpSecret = null;
        user.IsTotpEnabled = false;
        await _context.SaveChangesAsync();

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        await _auditService.LogAsync(username, "TOTP_WYLACZONE", "Uzytkownik wylaczyl dwuskladnikowe uwierzytelnianie TOTP.", ip, true);

        SuccessMessage = "Uwierzytelnianie dwuskladnikowe TOTP zostalo wylaczone.";
        IsTotpEnabled = false;
        return await OnGetAsync();
    }
}
