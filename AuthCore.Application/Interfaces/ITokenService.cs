using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace AuthCore.Application.Interfaces
{
    public interface ITokenService
    {
        Task<string> GenerateAccessTokenAsync(IdentityUser user, IEnumerable<string> roles);
        Task<string> GenerateRefreshTokenAsync();
        ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
    }
}
