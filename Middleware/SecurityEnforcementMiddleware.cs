using System.Security.Claims;
using cyberbezpieczenstwolab.Data;
using cyberbezpieczenstwolab.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

namespace cyberbezpieczenstwolab.Middleware;

public class SecurityEnforcementMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityEnforcementMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, IServiceProvider serviceProvider)
    {
        var path = context.Request.Path.Value?.ToLowerInvariant() ?? string.Empty;

        if (path.StartsWith("/lib") || path.StartsWith("/css") || path.StartsWith("/js") || path.StartsWith("/favicon.ico") || path == "/api/session-status")
        {
            await _next(context);
            return;
        }

        if (context.User.Identity?.IsAuthenticated == true)
        {
            using var scope = serviceProvider.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var auditService = scope.ServiceProvider.GetRequiredService<IAuditService>();

            var policy = await db.SecurityPolicies.AsNoTracking().FirstOrDefaultAsync();
            int idleTimeoutMinutes = policy?.SessionIdleTimeoutMinutes ?? 15;
            context.Items["SessionIdleTimeoutMinutes"] = idleTimeoutMinutes;

            var lastActivityStr = context.Session.GetString("LastActivityUtc");
            var now = DateTimeOffset.UtcNow;

            if (!string.IsNullOrEmpty(lastActivityStr) && DateTimeOffset.TryParse(lastActivityStr, out var lastActivity))
            {
                if (now - lastActivity >= TimeSpan.FromMinutes(idleTimeoutMinutes))
                {
                    var username = context.User.Identity?.Name ?? "Nieznany";
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    context.Session.Clear();

                    await auditService.LogAsync(username, "WYLOGOWANIE_BEZCZYNNOŚĆ", $"Sesja wygasla po {idleTimeoutMinutes} min bezczynnosci.", context.Connection.RemoteIpAddress?.ToString(), true);

                    if (!path.StartsWith("/account/login"))
                    {
                        context.Response.Redirect("/Account/Login?timeout=1");
                        return;
                    }
                }
            }

            context.Session.SetString("LastActivityUtc", now.ToString("o"));

            var mustChangePassword = context.User.FindFirst("MustChangePassword")?.Value;
            if (mustChangePassword == "True" || mustChangePassword == "true")
            {
                if (!path.StartsWith("/account/forcechangepassword") && !path.StartsWith("/account/logout") && !path.StartsWith("/api/"))
                {
                    context.Response.Redirect("/Account/ForceChangePassword");
                    return;
                }
            }
        }

        await _next(context);
    }
}
