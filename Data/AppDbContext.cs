using cyberbezpieczenstwolab.Models;
using Microsoft.EntityFrameworkCore;

namespace cyberbezpieczenstwolab.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();
    public DbSet<PasswordHistory> PasswordHistories => Set<PasswordHistory>();
    public DbSet<SecurityPolicy> SecurityPolicies => Set<SecurityPolicy>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<Article> Articles => Set<Article>();
    public DbSet<ArticleComment> ArticleComments => Set<ArticleComment>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<User>(entity =>
        {
            entity.HasIndex(u => u.Username).IsUnique();
            entity.Property(u => u.Username).HasMaxLength(50).IsRequired();
            entity.Property(u => u.Role).HasMaxLength(30).IsRequired();
        });

        modelBuilder.Entity<PasswordHistory>(entity =>
        {
            entity.HasOne(ph => ph.User)
                  .WithMany(u => u.PasswordHistories)
                  .HasForeignKey(ph => ph.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
