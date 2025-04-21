using AVP.AuthCore.Application.Common.Results;
using AVP.AuthCore.Application.DTOs;

namespace AVP.AuthCore.Application.Interfaces
{
    public interface IAuthService
    {
        Task<OperationResult<AuthResponse>> RegisterAsync(RegisterRequest request);
        Task<OperationResult<AuthResponse>> LoginAsync(LoginRequest request);
        Task<OperationResult<AuthResponse>> RefreshTokenAsync(RefreshRequest request);
        Task<OperationResult> RevokeRefreshTokenAsync(string refreshToken);
    }
}
