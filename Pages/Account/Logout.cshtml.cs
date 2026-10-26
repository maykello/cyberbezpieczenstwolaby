using cyberbezpieczenstwolab.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace cyberbezpieczenstwolab.Pages.Account;

public class LogoutModel : PageModel
{
    private readonly IAuditService _auditService;

    public LogoutModel(IAuditService auditService)
    {
        _auditService = auditService;
    }

    public IActionResult OnGet()
    {
        return RedirectToPage("/Index");
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var username = User.Identity?.Name;
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        HttpContext.Session.Clear();

        if (!string.IsNullOrEmpty(username))
        {
            await _auditService.LogAsync(username, "WYLOGOWANIE_RECZNE", "Uzytkownik wylogowal sie recznie.", ip, true);
        }

        return RedirectToPage("/Account/Login");
    }
}
