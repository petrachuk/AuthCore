using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace AuthCore.Persistence
{
    public class AuthDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
    {
        public AuthDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<AuthDbContext>();

            // загружаем конфигурацию из переменных окружения
            var config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetParent(Directory.GetCurrentDirectory())?.FullName ?? throw new InvalidOperationException())
                .AddJsonFile("AuthCore.API/appsettings.json")
                .AddEnvironmentVariables()
                .Build();

            // получаем строку подключения из конфигурации
            var connectionString = config.GetConnectionString("DefaultConnection");

            // настройка DbContext с использованием строки подключения
            optionsBuilder.UseNpgsql(connectionString); // Для PostgreSQL
            // optionsBuilder.UseSqlServer(connectionString);  // Для SQL Server

            return new AuthDbContext(optionsBuilder.Options);
        }
    }
}
