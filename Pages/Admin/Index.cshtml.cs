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
public class IndexModel : PageModel
{
    private readonly AppDbContext _context;
    private readonly IPasswordService _passwordService;
    private readonly IAuditService _auditService;

    public IndexModel(
        AppDbContext context,
        IPasswordService passwordService,
        IAuditService auditService)
    {
        _context = context;
        _passwordService = passwordService;
        _auditService = auditService;
    }

    public List<User> UsersList { get; set; } = [];
    public bool IsReadOnly { get; set; }
    public string? GeneratedPasswordNotice { get; set; }
    public string? ErrorMessage { get; set; }
    public string? SuccessMessage { get; set; }

    [BindProperty]
    public CreateUserModel CreateUser { get; set; } = new();

    public class CreateUserModel
    {
        [Required(ErrorMessage = "Login jest wymagany.")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Login musi miec od 3 do 50 znakow.")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Wybierz role dla uzytkownika.")]
        public string Role { get; set; } = AppRoles.Czytelnik;
    }

    public async Task OnGetAsync()
    {
        IsReadOnly = !User.IsInRole(AppRoles.Administrator);
        UsersList = await _context.Users.OrderBy(u => u.Id).ToListAsync();

        if (TempData["GeneratedPasswordNotice"] != null)
        {
            GeneratedPasswordNotice = TempData["GeneratedPasswordNotice"]?.ToString();
        }

        if (TempData["SuccessMessage"] != null)
        {
            SuccessMessage = TempData["SuccessMessage"]?.ToString();
        }

        if (TempData["ErrorMessage"] != null)
        {
            ErrorMessage = TempData["ErrorMessage"]?.ToString();
        }

        RolePermissionsMatrix = BuildRolePermissionsMatrix();
    }

    public List<RolePermissionRow> RolePermissionsMatrix { get; set; } = [];

    public class RolePermissionRow
    {
        public string Operation { get; set; } = string.Empty;
        public Dictionary<string, string> Access { get; set; } = new();
    }

    private static List<RolePermissionRow> BuildRolePermissionsMatrix()
    {
        var operations = new (string Operation, Func<string, string> Evaluator)[]
        {
            ("Logowanie i zmiana własnego hasła", _ => "Dozwolone"),
            ("Podgląd listy użytkowników (/Admin/Index)", role => (role == AppRoles.Administrator || role == AppRoles.Audytor) ? "Dozwolone" : "Brak dostępu"),
            ("Zarządzanie kontami (dodawanie/edycja/blokada/reset/usuwanie)", role => role == AppRoles.Administrator ? "Dozwolone" : (role == AppRoles.Audytor ? "Tylko odczyt" : "Brak dostępu")),
            ("Podgląd polityki bezpieczeństwa (/Admin/Policy)", role => (role == AppRoles.Administrator || role == AppRoles.Audytor) ? "Dozwolone" : "Brak dostępu"),
            ("Modyfikacja polityki bezpieczeństwa", role => role == AppRoles.Administrator ? "Dozwolone" : (role == AppRoles.Audytor ? "Tylko odczyt" : "Brak dostępu")),
            ("Dostęp do dziennika audytu (/Admin/Audit)", role => (role == AppRoles.Administrator || role == AppRoles.Audytor) ? "Dozwolone" : "Brak dostępu"),
            ("Publikacja nowych artykułów (/Articles)", role => (role == AppRoles.Administrator || role == AppRoles.Redaktor) ? "Dozwolone" : "Brak dostępu"),
            ("Dodawanie komentarzy pod artykułami", _ => "Dozwolone"),
            ("Moderacja komentarzy i usuwanie artykułów", role => (role == AppRoles.Administrator || role == AppRoles.Audytor) ? "Dozwolone" : "Brak dostępu")
        };

        var matrix = new List<RolePermissionRow>();
        foreach (var op in operations)
        {
            var row = new RolePermissionRow { Operation = op.Operation };
            foreach (var role in AppRoles.All)
            {
                row.Access[role] = op.Evaluator(role);
            }
            matrix.Add(row);
        }
        return matrix;
    }

    public async Task<IActionResult> OnPostAddUserAsync()
    {
        if (!User.IsInRole(AppRoles.Administrator))
        {
            var ipForbidden = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
            await _auditService.LogAsync(User.Identity?.Name, "AUDYTOR_PROBA_MODYFIKACJI_403", "Audytor probowal dodac uzytkownika.", ipForbidden, false);
            return Forbid();
        }

        if (!ModelState.IsValid)
        {
            await OnGetAsync();
            return Page();
        }

        bool exists = await _context.Users.AnyAsync(u => u.Username.ToLower() == CreateUser.Username.ToLower());
        if (exists)
        {
            ErrorMessage = "Uzytkownik o podanym loginie juz istnieje w systemie.";
            await OnGetAsync();
            return Page();
        }

        string otp = _passwordService.GenerateOneTimePassword();
        var (hash, salt) = _passwordService.HashPassword(otp);

        var policy = await _context.SecurityPolicies.FirstOrDefaultAsync();
        int tempHours = policy?.TemporaryPasswordValidityHours ?? 24;

        var newUser = new User
        {
            Username = CreateUser.Username,
            Role = CreateUser.Role,
            PasswordHash = hash,
            Salt = salt,
            IsActive = true,
            MustChangePassword = true,
            IsTemporaryPassword = true,
            TemporaryPasswordExpiresAt = DateTime.UtcNow.AddHours(tempHours),
            PasswordExpiresAt = DateTime.UtcNow.AddDays(policy?.PasswordValidityDays ?? 90),
            CreatedAt = DateTime.UtcNow
        };

        _context.Users.Add(newUser);
        await _context.SaveChangesAsync();

        _context.PasswordHistories.Add(new PasswordHistory
        {
            UserId = newUser.Id,
            PasswordHash = hash,
            Salt = salt,
            CreatedAt = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        await _auditService.LogAsync(User.Identity?.Name, "DODANIE_UZYTKOWNIKA", $"Utworzono konto {newUser.Username} z rola {newUser.Role} i haslem jednorazowym ({tempHours}h).", ip, true);

        TempData["GeneratedPasswordNotice"] = $"Utworzono konto '{newUser.Username}'. Nadane haslo jednorazowe (wazne {tempHours}h): {otp}";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostToggleBlockAsync(int id)
    {
        if (!User.IsInRole(AppRoles.Administrator))
        {
            var ipForbidden = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
            await _auditService.LogAsync(User.Identity?.Name, "AUDYTOR_PROBA_MODYFIKACJI_403", "Audytor probowal zablokowac/odblokowac uzytkownika.", ipForbidden, false);
            return Forbid();
        }

        var user = await _context.Users.FindAsync(id);
        if (user == null)
        {
            return RedirectToPage();
        }

        if (user.Username.Equals(User.Identity?.Name, StringComparison.OrdinalIgnoreCase))
        {
            TempData["ErrorMessage"] = "Nie mozesz zablokowac wlasnego konta administratora.";
            return RedirectToPage();
        }

        user.IsActive = !user.IsActive;
        await _context.SaveChangesAsync();

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        string actionName = user.IsActive ? "ODBLOKOWANIE_KONTA" : "BLOKADA_KONTA";
        await _auditService.LogAsync(User.Identity?.Name, actionName, $"Zmieniono status uzytkownika {user.Username} na {(user.IsActive ? "Aktywny" : "Zablokowany")}.", ip, true);

        TempData["SuccessMessage"] = $"Zmieniono status uzytkownika '{user.Username}'.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostResetPasswordAsync(int id)
    {
        if (!User.IsInRole(AppRoles.Administrator))
        {
            var ipForbidden = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
            await _auditService.LogAsync(User.Identity?.Name, "AUDYTOR_PROBA_MODYFIKACJI_403", "Audytor probowal zresetowac haslo.", ipForbidden, false);
            return Forbid();
        }

        var user = await _context.Users.FindAsync(id);
        if (user == null)
        {
            return RedirectToPage();
        }

        string otp = _passwordService.GenerateOneTimePassword();
        var (hash, salt) = _passwordService.HashPassword(otp);

        var policy = await _context.SecurityPolicies.FirstOrDefaultAsync();
        int tempHours = policy?.TemporaryPasswordValidityHours ?? 24;

        user.PasswordHash = hash;
        user.Salt = salt;
        user.MustChangePassword = true;
        user.IsTemporaryPassword = true;
        user.TemporaryPasswordExpiresAt = DateTime.UtcNow.AddHours(tempHours);

        _context.PasswordHistories.Add(new PasswordHistory
        {
            UserId = user.Id,
            PasswordHash = hash,
            Salt = salt,
            CreatedAt = DateTime.UtcNow
        });

        await _context.SaveChangesAsync();

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        await _auditService.LogAsync(User.Identity?.Name, "RESET_HASLA", $"Zresetowano haslo uzytkownikowi {user.Username} (haslo jednorazowe {tempHours}h).", ip, true);

        TempData["GeneratedPasswordNotice"] = $"Zresetowano haslo dla '{user.Username}'. Nowe haslo jednorazowe (wazne {tempHours}h): {otp}";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostDeleteUserAsync(int id)
    {
        if (!User.IsInRole(AppRoles.Administrator))
        {
            var ipForbidden = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
            await _auditService.LogAsync(User.Identity?.Name, "AUDYTOR_PROBA_MODYFIKACJI_403", "Audytor probowal usunac uzytkownika.", ipForbidden, false);
            return Forbid();
        }

        var user = await _context.Users.FindAsync(id);
        if (user == null)
        {
            return RedirectToPage();
        }

        if (user.Username.Equals(User.Identity?.Name, StringComparison.OrdinalIgnoreCase))
        {
            TempData["ErrorMessage"] = "Nie mozesz usunac biezacego uzytkownika administratora.";
            return RedirectToPage();
        }

        string deletedName = user.Username;
        _context.Users.Remove(user);
        await _context.SaveChangesAsync();

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        await _auditService.LogAsync(User.Identity?.Name, "USUNIECIE_UZYTKOWNIKA", $"Usunieto uzytkownika {deletedName}.", ip, true);

        TempData["SuccessMessage"] = $"Uzytkownik '{deletedName}' zostal trwale usuniety.";
        return RedirectToPage();
    }
}
