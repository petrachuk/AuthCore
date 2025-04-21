using AVP.AuthCore.Application.DTOs;

namespace AVP.AuthCore.Application.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResponse> RegisterAsync(RegisterRequest request);
        Task<AuthResponse> LoginAsync(LoginRequest request);
        Task<AuthResponse> RefreshTokenAsync(RefreshRequest request);
        Task RevokeRefreshTokenAsync(string refreshToken);
    }
}
