using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using AuthCore.Persistence;

namespace AuthCore.Infrastructure.HostedServices
{
    /// <summary>
    /// Автоочиста RefreshToken
    /// </summary>
    public class RefreshTokenCleanupService(
        IServiceScopeFactory scopeFactory,
        ILogger<RefreshTokenCleanupService> logger)
        : BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromHours(6), stoppingToken); // Периодичность

                using var scope = scopeFactory.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

                var now = DateTime.UtcNow;
                var expiredTokens = await db.RefreshTokens
                    .Where(t => t.Expires < now)
                    .ToListAsync(stoppingToken);

                if (expiredTokens.Count == 0) continue;

                db.RefreshTokens.RemoveRange(expiredTokens);
                await db.SaveChangesAsync(stoppingToken);
                logger.LogInformation("Удалено {Count} просроченных refresh-токенов", expiredTokens.Count);
            }
        }
    }

}
