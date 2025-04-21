using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using AVP.AuthCore.Application.Interfaces;
using AVP.AuthCore.Application.DTOs;
using AVP.AuthCore.Persistence;
using AVP.AuthCore.Persistence.Entities;

namespace AVP.AuthCore.Application.Services
{
    public class AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ITokenService tokenService,
        AuthDbContext context) : IAuthService
    {
        public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
        {
            var user = new ApplicationUser { UserName = request.Email, Email = request.Email };
            var result = await userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));
            }

            var accessToken = await tokenService.GenerateAccessTokenAsync(user);
            var refreshToken = await tokenService.GenerateRefreshTokenAsync();

            var expires = DateTime.UtcNow.AddDays(7);

            context.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                Expires = expires,
                UserId = user.Id
            });

            await context.SaveChangesAsync();

            return new AuthResponse(true, accessToken, refreshToken, expires, []);
        }

        public async Task<AuthResponse> LoginAsync(LoginRequest request)
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
                throw new Exception("Invalid credentials");

            var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            if (!result.Succeeded)
                throw new Exception("Invalid credentials");

            var accessToken = await tokenService.GenerateAccessTokenAsync(user);
            var refreshToken = await tokenService.GenerateRefreshTokenAsync();

            var expires = DateTime.UtcNow.AddDays(7);

            context.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                Expires = expires,
                UserId = user.Id
            });

            await context.SaveChangesAsync();

            return new AuthResponse(true, accessToken, refreshToken, expires, []);
        }

        public async Task<AuthResponse> RefreshTokenAsync(RefreshRequest request)
        {
            var principal = tokenService.GetPrincipalFromExpiredToken(request.AccessToken);
            var userId = principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (userId is null)
                throw new Exception("Invalid access token");

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
                throw new Exception("User not found");

            var storedToken = await context.RefreshTokens
                .Where(x => x.Token == request.RefreshToken && x.UserId == user.Id && !x.Revoked)
                .FirstOrDefaultAsync();

            if (storedToken == null || storedToken.Expires < DateTime.UtcNow)
                throw new Exception("Invalid or expired refresh token");

            // отзыв старого токена
            storedToken.Revoked = true;
            var newRefreshToken = await tokenService.GenerateRefreshTokenAsync();

            var expires = DateTime.UtcNow.AddDays(7);

            context.RefreshTokens.Add(new RefreshToken
            {
                Token = newRefreshToken,
                Expires = expires,
                UserId = user.Id,
                ReplacedByToken = storedToken.Token
            });

            await context.SaveChangesAsync();

            var newAccessToken = await tokenService.GenerateAccessTokenAsync(user);

            return new AuthResponse(true, newAccessToken, newRefreshToken, expires, []);
        }

        public async Task RevokeRefreshTokenAsync(string refreshToken)
        {
            var token = await context.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == refreshToken);

            if (token != null)
            {
                token.Revoked = true;
                await context.SaveChangesAsync();
            }
        }
    }
}
