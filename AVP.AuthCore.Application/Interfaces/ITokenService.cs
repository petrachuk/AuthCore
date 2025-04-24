using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace AVP.AuthCore.Application.Interfaces
{
    public interface ITokenService
    {
        Task<string> GenerateAccessTokenAsync(IdentityUser user, IList<string> roles);
        Task<string> GenerateRefreshTokenAsync();
        ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
    }
}
