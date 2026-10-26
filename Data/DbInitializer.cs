using cyberbezpieczenstwolab.Models;
using cyberbezpieczenstwolab.Services;
using Microsoft.EntityFrameworkCore;

namespace cyberbezpieczenstwolab.Data;

public static class DbInitializer
{
    public static async Task InitializeAsync(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var passwordService = scope.ServiceProvider.GetRequiredService<IPasswordService>();

        await context.Database.EnsureCreatedAsync();

        try
        {
            await context.Database.ExecuteSqlRawAsync("ALTER TABLE SecurityPolicies ADD COLUMN TemporaryPasswordValidityHours INTEGER NOT NULL DEFAULT 24;");
        }
        catch
        {
        }

        try
        {
            await context.Database.ExecuteSqlRawAsync(@"
                CREATE TABLE IF NOT EXISTS Articles (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Title TEXT NOT NULL,
                    Content TEXT NOT NULL,
                    AuthorUsername TEXT NOT NULL,
                    CreatedAt TEXT NOT NULL
                );");

            await context.Database.ExecuteSqlRawAsync(@"
                CREATE TABLE IF NOT EXISTS ArticleComments (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ArticleId INTEGER NOT NULL,
                    AuthorUsername TEXT NOT NULL,
                    Content TEXT NOT NULL,
                    CreatedAt TEXT NOT NULL,
                    IsModerated INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (ArticleId) REFERENCES Articles(Id) ON DELETE CASCADE
                );");
        }
        catch
        {
        }

        if (!await context.SecurityPolicies.AnyAsync())
        {
            var policy = new SecurityPolicy
            {
                MinPasswordLength = 15,
                EnableDateAndYearRestriction = true,
                PasswordValidityDays = 90,
                SessionIdleTimeoutMinutes = 15,
                TemporaryPasswordValidityHours = 24,
                UpdatedAt = DateTime.UtcNow
            };
            context.SecurityPolicies.Add(policy);
            await context.SaveChangesAsync();
        }

        var testUsers = new (string Username, string Role, string RawPassword)[]
        {
            ("admin", AppRoles.Administrator, "zaq1@WSXzaq1@WSX"),
            ("audytor1", AppRoles.Audytor, "zaq1@WSXzaq1@WSX"),
            ("audytor2", AppRoles.Audytor, "zaq1@WSXzaq1@WSX"),
            ("redaktor1", AppRoles.Redaktor, "zaq1@WSXzaq1@WSX"),
            ("redaktor2", AppRoles.Redaktor, "zaq1@WSXzaq1@WSX")
        };

        foreach (var item in testUsers)
        {
            if (!await context.Users.AnyAsync(u => u.Username == item.Username))
            {
                var (hash, salt) = passwordService.HashPassword(item.RawPassword);
                var user = new User
                {
                    Username = item.Username,
                    Role = item.Role,
                    PasswordHash = hash,
                    Salt = salt,
                    IsActive = true,
                    MustChangePassword = false,
                    IsTemporaryPassword = false,
                    PasswordExpiresAt = DateTime.UtcNow.AddDays(90),
                    CreatedAt = DateTime.UtcNow
                };
                context.Users.Add(user);
                await context.SaveChangesAsync();

                context.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = user.Id,
                    PasswordHash = hash,
                    Salt = salt,
                    CreatedAt = DateTime.UtcNow
                });
                await context.SaveChangesAsync();
            }
        }

        var czytelnicy = await context.Users.Where(u => u.Role == AppRoles.Czytelnik || u.Username.StartsWith("czytelnik")).ToListAsync();
        if (czytelnicy.Count > 0)
        {
            context.Users.RemoveRange(czytelnicy);
            await context.SaveChangesAsync();
        }

        var adminUser = await context.Users.FirstOrDefaultAsync(u => u.Username == "admin");
        if (adminUser != null)
        {
            var (newHash, newSalt) = passwordService.HashPassword("zaq1@WSXzaq1@WSX");
            adminUser.PasswordHash = newHash;
            adminUser.Salt = newSalt;
            await context.SaveChangesAsync();
        }

        if (!await context.AuditLogs.AnyAsync())
        {
            context.AuditLogs.Add(new AuditLog
            {
                Timestamp = DateTime.UtcNow,
                Username = "SYSTEM",
                Action = "INICJALIZACJA_BAZY",
                Details = "Pomyslnie zainicjalizowano baze SQLite i konto administratora.",
                IpAddress = "127.0.0.1",
                IsSuccess = true
            });
            await context.SaveChangesAsync();
        }
    }
}
