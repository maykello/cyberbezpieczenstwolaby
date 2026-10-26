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
public class PolicyModel : PageModel
{
    private readonly AppDbContext _context;
    private readonly IAuditService _auditService;

    public PolicyModel(AppDbContext context, IAuditService auditService)
    {
        _context = context;
        _auditService = auditService;
    }

    public bool IsReadOnly { get; set; }
    public string? SuccessMessage { get; set; }
    public string? ErrorMessage { get; set; }

    [BindProperty]
    public PolicyInputModel Input { get; set; } = new();

    public class PolicyInputModel
    {
        [Required(ErrorMessage = "Minimalna dlugosc hasla jest wymagana.")]
        [Range(8, 128, ErrorMessage = "Dlugosc hasla musi wynosic od 8 do 128 znakow.")]
        public int MinPasswordLength { get; set; } = 15;

        public bool EnableDateAndYearRestriction { get; set; } = true;

        [Required(ErrorMessage = "Waznosc hasla w dniach jest wymagana.")]
        [Range(1, 365, ErrorMessage = "Waznosc hasla musi wynosic od 1 do 365 dni.")]
        public int PasswordValidityDays { get; set; } = 90;

        [Required(ErrorMessage = "Czas bezczynnosci sesji jest wymagany.")]
        [Range(1, 1440, ErrorMessage = "Czas bezczynnosci sesji musi wynosic od 1 do 1440 minut.")]
        public int SessionIdleTimeoutMinutes { get; set; } = 15;

        [Required(ErrorMessage = "Czas waznosci hasla jednorazowego jest wymagany.")]
        [Range(1, 168, ErrorMessage = "Czas waznosci hasla jednorazowego musi wynosic od 1 do 168 godzin (do 7 dni).")]
        public int TemporaryPasswordValidityHours { get; set; } = 24;
    }

    public async Task OnGetAsync()
    {
        IsReadOnly = !User.IsInRole(AppRoles.Administrator);

        var policy = await _context.SecurityPolicies.FirstOrDefaultAsync();
        if (policy != null)
        {
            Input = new PolicyInputModel
            {
                MinPasswordLength = policy.MinPasswordLength,
                EnableDateAndYearRestriction = policy.EnableDateAndYearRestriction,
                PasswordValidityDays = policy.PasswordValidityDays,
                SessionIdleTimeoutMinutes = policy.SessionIdleTimeoutMinutes,
                TemporaryPasswordValidityHours = policy.TemporaryPasswordValidityHours
            };
        }
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!User.IsInRole(AppRoles.Administrator))
        {
            var ipForbidden = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
            await _auditService.LogAsync(User.Identity?.Name, "AUDYTOR_PROBA_MODYFIKACJI_403", "Audytor probowal zmienic parametry polityki bezpieczenstwa.", ipForbidden, false);
            return Forbid();
        }

        if (!ModelState.IsValid)
        {
            IsReadOnly = false;
            return Page();
        }

        var policy = await _context.SecurityPolicies.FirstOrDefaultAsync();
        if (policy == null)
        {
            policy = new SecurityPolicy();
            _context.SecurityPolicies.Add(policy);
        }

        policy.MinPasswordLength = Input.MinPasswordLength;
        policy.EnableDateAndYearRestriction = Input.EnableDateAndYearRestriction;
        policy.PasswordValidityDays = Input.PasswordValidityDays;
        policy.SessionIdleTimeoutMinutes = Input.SessionIdleTimeoutMinutes;
        policy.TemporaryPasswordValidityHours = Input.TemporaryPasswordValidityHours;
        policy.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        await _auditService.LogAsync(User.Identity?.Name, "AKTUALIZACJA_POLITYKI", $"MinDlugosc={policy.MinPasswordLength}, ZakazDat={policy.EnableDateAndYearRestriction}, WaznoscDni={policy.PasswordValidityDays}, TimeoutMin={policy.SessionIdleTimeoutMinutes}, WaznoscJednorazowegoGodz={policy.TemporaryPasswordValidityHours}", ip, true);

        SuccessMessage = "Parametry polityki bezpieczenstwa zostaly zaktualizowane.";
        IsReadOnly = false;
        return Page();
    }
}
