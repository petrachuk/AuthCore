using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using AVP.AuthCore.Application.Interfaces;
using System.Security.Cryptography;

namespace AVP.AuthCore.Application.Services
{
    public class TokenService(IConfiguration config) : ITokenService
    {
        public Task<string> GenerateAccessTokenAsync(IdentityUser user, IList<string> roles)
        {
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Id),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            
            // добавление ролей
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JwtSettings:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // создаем JWT-токен
            var token = new JwtSecurityToken(
                issuer: config["JwtSettings:Issuer"],
                audience: config["JwtSettings:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15),   // время действия 15 минут
                signingCredentials: creds);

            return Task.FromResult(new JwtSecurityTokenHandler().WriteToken(token));
        }

        public Task<string> GenerateRefreshTokenAsync()
        {
            return Task.FromResult(Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)));
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,   // мы не проверяем, кому был предназначен токен
                ValidateIssuer = false,     // и кто его выпустил
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JwtSettings:Key"])),
                ValidateLifetime = false // важно! мы извлекаем даже из просроченного токена
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

            if (securityToken is not JwtSecurityToken jwtToken || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }
    }
}
