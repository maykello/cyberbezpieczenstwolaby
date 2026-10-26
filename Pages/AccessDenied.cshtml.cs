using Microsoft.AspNetCore.Mvc.RazorPages;

namespace cyberbezpieczenstwolab.Pages;

public class AccessDeniedModel : PageModel
{
    public string? CurrentRole { get; set; }
    public string? CurrentUser { get; set; }

    public void OnGet()
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        CurrentUser = User.Identity?.Name ?? "Niezalogowany";
        CurrentRole = User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value ?? "Brak roli";
    }
}
