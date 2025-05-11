using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using AuthCore.Persistence.Configurations;
using AuthCore.Persistence.Entities;


namespace AuthCore.Persistence
{
    public class AuthDbContext(DbContextOptions<AuthDbContext> options) : IdentityDbContext<ApplicationUser>(options)
    {
        // Можно добавить дополнительные таблицы, если нужно
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.ApplyConfiguration(new RefreshTokenConfiguration());
            // другие конфигурации
        }
    }
}
