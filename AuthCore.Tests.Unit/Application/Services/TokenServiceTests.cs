using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using AuthCore.Application.Services;
using AuthCore.Abstractions.Settings;
using System.Text;

namespace AuthCore.Tests.Unit.Application.Services
{
    public class TokenServiceTests
    {
        private readonly JwtSettings _jwtSettings;
        private readonly TokenService _tokenService;

        public TokenServiceTests()
        {
            _jwtSettings = new JwtSettings
            {
                Key = "super_secret_key_1234567890_super_secret_key",
                Issuer = "TestIssuer",
                Audience = "TestAudience",
                AccessTokenLifetimeMinutes = 15,
                RefreshTokenLifetimeDays = 7
            };

            _tokenService = new TokenService(_jwtSettings);
        }

        /// <summary>
        /// Генерирует токен, проверяет его подпись, issuer и audiences
        /// </summary>
        [Fact]
        public async Task GenerateAccessTokenAsync_ValidUserAndRoles_ReturnsToken()
        {
            // Arrange
            var user = new IdentityUser { Id = Guid.NewGuid().ToString() };
            var roles = new List<string> { "Admin", "User" };

            // Act
            var token = await _tokenService.GenerateAccessTokenAsync(user, roles);

            // Assert
            Assert.False(string.IsNullOrEmpty(token));

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidAudience = _jwtSettings.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key)),
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,

                NameClaimType = JwtRegisteredClaimNames.Sub
            }, out var validatedToken);

            Assert.NotNull(principal);
            Assert.IsType<JwtSecurityToken>(validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            Assert.Equal(_jwtSettings.Issuer, jwtToken.Issuer);
            Assert.Equal(_jwtSettings.Audience, jwtToken.Audiences.First());
        }

        /// <summary>
        /// Проверяет, что refresh токен корректно сформирован (64 байта)
        /// </summary>
        [Fact]
        public async Task GenerateRefreshTokenAsync_ReturnsBase64String()
        {
            // Act
            var refreshToken = await _tokenService.GenerateRefreshTokenAsync();

            // Assert
            Assert.False(string.IsNullOrEmpty(refreshToken));

            var bytes = Convert.FromBase64String(refreshToken);
            Assert.Equal(64, bytes.Length); // должно быть 64 байта
        }

        /// <summary>
        /// Извлекает ClaimsPrincipal из токена без проверки срока действия
        /// </summary>
        [Fact]
        public async Task GetPrincipalFromExpiredToken_ValidToken_ReturnsPrincipal()
        {
            // Arrange
            var user = new IdentityUser { Id = Guid.NewGuid().ToString() };
            var roles = new List<string> { "Admin" };
            var token = await _tokenService.GenerateAccessTokenAsync(user, roles);

            // Act
            var principal = _tokenService.GetPrincipalFromExpiredToken(token);

            // Assert
            Assert.NotNull(principal);

            var subClaim = principal.FindFirst(ClaimTypes.NameIdentifier);
            Assert.Equal(user.Id, subClaim?.Value);

            var roleClaim = principal.FindFirst(ClaimTypes.Role);
            Assert.Equal("Admin", roleClaim?.Value);
        }

        // Параметризованный тест
        [Theory]
        [InlineData("this-is-not-a-valid-jwt", typeof(SecurityTokenMalformedException), "IDX12741")]
        [InlineData("invalid.token.here", typeof(ArgumentException), "IDX12729")]
        [InlineData("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsIm5hbWUiOiJKb2huIEdvbGQiLCJhZG1pbiI6dHJ1ZX0K.zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", typeof(SecurityTokenInvalidSignatureException), null)]
        public void GetPrincipalFromExpiredToken_InvalidFormat_ThrowsExpectedException(string token, Type expectedExceptionType, string? expectedMessage)
        {
            // Act & Assert
            var ex = Assert.Throws(expectedExceptionType, () => _tokenService.GetPrincipalFromExpiredToken(token));
            Assert.IsType(expectedExceptionType, ex); // Проверяем, что выбрасывается правильный тип исключения

            if (expectedMessage != null)
            {
                Assert.Contains(expectedMessage, ex.Message); // Проверяем, что сообщение содержит ожидаемую строку
            }
        }
    }
}
