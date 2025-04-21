using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using AVP.AuthCore.Application.Interfaces;
using AVP.AuthCore.Application.DTOs;
using AVP.AuthCore.Persistence;
using AVP.AuthCore.Persistence.Entities;
using AVP.AuthCore.Application.Common.Results;

namespace AVP.AuthCore.Application.Services
{
    public class AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ITokenService tokenService,
        AuthDbContext context) : IAuthService
    {
        public async Task<OperationResult<AuthResponse>> RegisterAsync(RegisterRequest request)
        {
            var user = new ApplicationUser { UserName = request.Email, Email = request.Email };
            var result = await userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
                return OperationResult<AuthResponse>.Fail(result.Errors.Select(e => e.Description).ToArray());

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

            return OperationResult<AuthResponse>.Ok(new AuthResponse(accessToken, refreshToken, expires));
        }

        public async Task<OperationResult<AuthResponse>> LoginAsync(LoginRequest request)
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
                return OperationResult<AuthResponse>.Fail("Invalid credentials");

            var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            if (!result.Succeeded)
                return OperationResult<AuthResponse>.Fail("Invalid credentials");

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

            return OperationResult<AuthResponse>.Ok(new AuthResponse(accessToken, refreshToken, expires));
        }

        public async Task<OperationResult<AuthResponse>> RefreshTokenAsync(RefreshRequest request)
        {
            var principal = tokenService.GetPrincipalFromExpiredToken(request.AccessToken);
            var userId = principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (userId is null)
                return OperationResult<AuthResponse>.Fail("Invalid access token");

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
                return OperationResult<AuthResponse>.Fail("User not found");

            var storedToken = await context.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == request.RefreshToken && x.UserId == user.Id && !x.Revoked);

            if (storedToken == null || storedToken.Expires < DateTime.UtcNow)
                return OperationResult<AuthResponse>.Fail("Invalid or expired refresh token");

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

            return OperationResult<AuthResponse>.Ok(new AuthResponse(newAccessToken, newRefreshToken, expires));
        }

        public async Task<OperationResult> RevokeRefreshTokenAsync(string refreshToken)
        {
            var token = await context.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == refreshToken);

            if (token == null)
                return OperationResult.Fail("Refresh token not found");

            if (token.Revoked)
                return OperationResult.Fail("Refresh token already revoked");

            token.Revoked = true;
            await context.SaveChangesAsync();

            return OperationResult.Ok();
        }
    }
}
