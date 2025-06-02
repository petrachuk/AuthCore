using AuthCore.Abstractions.Interfaces;
using AuthCore.Abstractions.Models;
using AuthCore.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthCore.Persistence.Stores
{
    public class DbRefreshTokenStore(AuthDbContext context) : IRefreshTokenStore
    {
        
        public async Task SaveRefreshTokenAsync(RefreshTokenInfo refreshToken)
        {
            var entity = new RefreshToken
            {
                Token = refreshToken.Token,
                UserId = refreshToken.UserId,
                Expires = refreshToken.Expires
            };

            context.RefreshTokens.Add(entity);
            await context.SaveChangesAsync();
        }

        public async Task<RefreshTokenInfo?> GetRefreshTokenAsync(string refreshToken)
        {
            var token = await context.RefreshTokens
                .FirstOrDefaultAsync(t => t.Token == refreshToken);
            
            return token == null ? null : new RefreshTokenInfo
            {
                Token = token.Token,
                UserId = token.UserId,
                Expires = token.Expires
            };
        }

        public async Task DeleteRefreshTokenAsync(string refreshToken)
        {
            var token = await context.RefreshTokens.FirstOrDefaultAsync(t => t.Token == refreshToken);
            if (token != null)
            {
                context.RefreshTokens.Remove(token);
                await context.SaveChangesAsync();
            }
        }
    }
}
