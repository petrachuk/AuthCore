using AuthCore.Abstractions.Models;

namespace AuthCore.Abstractions.Interfaces
{
    public interface IRefreshTokenStore
    {
        Task<RefreshTokenInfo?> GetRefreshTokenAsync(string refreshToken);
        Task SaveRefreshTokenAsync(RefreshTokenInfo refreshToken);
        Task DeleteRefreshTokenAsync(string token);
    }
}