using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using AuthCore.Abstractions.Interfaces;
using AuthCore.Abstractions.Models;

namespace AuthCore.Persistence.Stores
{
    public class RedisRefreshTokenStore(IDistributedCache cache) : IRefreshTokenStore
    {
        public async Task SaveRefreshTokenAsync(RefreshTokenInfo refreshToken)
        {
            var data = new TokenData { UserId = refreshToken.UserId, Expires = refreshToken.Expires };
            var json = JsonSerializer.Serialize(data);

            var ttl = refreshToken.Expires - DateTime.UtcNow;
            if (ttl <= TimeSpan.Zero)
                throw new ArgumentException("Token expiration time must be in the future.", nameof(refreshToken));

            var options = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            };

            await cache.SetStringAsync(GetKey(refreshToken.Token), json, options);
        }

        public async Task<RefreshTokenInfo?> GetRefreshTokenAsync(string refreshToken)
        {
            var json = await cache.GetStringAsync(GetKey(refreshToken));

            if (string.IsNullOrEmpty(json)) return null;

            var data = JsonSerializer.Deserialize<TokenData>(json);
            if (data == null) return null;

            return new RefreshTokenInfo
            {
                Token = refreshToken,
                UserId = data.UserId,
                Expires = data.Expires
            };
        }

        public async Task DeleteRefreshTokenAsync(string refreshToken)
        {
            await cache.RemoveAsync(GetKey(refreshToken));
        }

        private static string GetKey(string token) => $"refreshToken:{token}";

        private record TokenData
        {
            public required string UserId { get; init; }
            public DateTime Expires { get; init; }
        }
    }
}
