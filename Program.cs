using cyberbezpieczenstwolab.Data;
using cyberbezpieczenstwolab.Middleware;
using cyberbezpieczenstwolab.Models;
using cyberbezpieczenstwolab.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<IPasswordService, PasswordService>();
builder.Services.AddScoped<ITotpService, TotpService>();
builder.Services.AddScoped<IAuditService, AuditService>();

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromHours(4);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
});

builder.Services.AddAntiforgery(options =>
{
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
});

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/AccessDenied";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.ExpireTimeSpan = TimeSpan.FromHours(4);
        options.SlidingExpiration = true;
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOrAuditor", policy => policy.RequireRole(AppRoles.Administrator, AppRoles.Audytor));
    options.AddPolicy("AdminOnly", policy => policy.RequireRole(AppRoles.Administrator));
});

builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizeFolder("/Admin", "AdminOrAuditor");
    options.Conventions.AllowAnonymousToPage("/Account/Login");
    options.Conventions.AllowAnonymousToPage("/Index");
    options.Conventions.AllowAnonymousToPage("/AccessDenied");
    options.Conventions.AllowAnonymousToPage("/Error");
});

var app = builder.Build();

await DbInitializer.InitializeAsync(app.Services);

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseStaticFiles();

app.UseRouting();

app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.UseMiddleware<SecurityEnforcementMiddleware>();

app.MapRazorPages();
app.MapGet("/api/keep-alive", () => Results.Ok(new { status = "active" }));

app.MapGet("/api/session-status", async (HttpContext context, AppDbContext db) =>
{
    if (context.User.Identity?.IsAuthenticated != true)
    {
        return Results.Ok(new { authenticated = false, remainingSeconds = 0 });
    }

    var policy = await db.SecurityPolicies.AsNoTracking().FirstOrDefaultAsync();
    int timeoutMinutes = policy?.SessionIdleTimeoutMinutes ?? 15;
    int totalSeconds = timeoutMinutes * 60;

    var lastActivityStr = context.Session.GetString("LastActivityUtc");
    int remainingSeconds = totalSeconds;

    if (!string.IsNullOrEmpty(lastActivityStr) && DateTimeOffset.TryParse(lastActivityStr, out var lastActivity))
    {
        var elapsed = (DateTimeOffset.UtcNow - lastActivity).TotalSeconds;
        remainingSeconds = Math.Max(0, (int)(totalSeconds - elapsed));
    }

    return Results.Ok(new
    {
        authenticated = true,
        remainingSeconds = remainingSeconds,
        totalSeconds = totalSeconds
    });
});

app.Run();
