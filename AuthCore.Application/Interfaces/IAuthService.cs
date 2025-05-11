using AuthCore.Application.Common.Results;
using AuthCore.Application.DTOs;

namespace AuthCore.Application.Interfaces
{
    public interface IAuthService
    {
        Task<OperationResult<AuthResponse>> RegisterAsync(RegisterRequest request);
        Task<OperationResult<AuthResponse>> LoginAsync(LoginRequest request);
        Task<OperationResult<AuthResponse>> RefreshTokenAsync(RefreshRequest request);
        Task<OperationResult> RevokeRefreshTokenAsync(string refreshToken);
    }
}
