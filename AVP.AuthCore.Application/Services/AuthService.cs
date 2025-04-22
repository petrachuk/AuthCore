using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using AVP.AuthCore.Application.Interfaces;
using AVP.AuthCore.Application.DTOs;
using AVP.AuthCore.Persistence;
using AVP.AuthCore.Persistence.Entities;
using AVP.AuthCore.Application.Common.Results;
using Microsoft.Extensions.Logging;

namespace AVP.AuthCore.Application.Services
{
    public class AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ITokenService tokenService,
        AuthDbContext context,
        ILogger<AuthService> logger) : IAuthService
    {
        public async Task<OperationResult<AuthResponse>> RegisterAsync(RegisterRequest request)
        {
            logger.LogInformation("Registration attempt for {Email}", request.Email);

            var user = new ApplicationUser { UserName = request.Email, Email = request.Email };
            var result = await userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                logger.LogWarning("Registration failed for {Email} with errors: {Errors}", request.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
                return OperationResult<AuthResponse>.Fail(result.Errors.Select(e => e.Description).ToArray());
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

            logger.LogInformation("User {Email} registered successfully", request.Email);
            return OperationResult<AuthResponse>.Ok(new AuthResponse(accessToken, refreshToken, expires));
        }

        public async Task<OperationResult<AuthResponse>> LoginAsync(LoginRequest request)
        {
            logger.LogInformation("Login attempt for {Email}", request.Email);

            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                logger.LogWarning("Login failed for {Email} with errors: Invalid credentials", request.Email);
                return OperationResult<AuthResponse>.Fail("Invalid credentials");
            }

            var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            if (!result.Succeeded)
            {
                logger.LogWarning("Login failed for {Email} with errors: Invalid credentials", request.Email);
                return OperationResult<AuthResponse>.Fail("Invalid credentials");
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

            logger.LogInformation("User {Email} logged in successfully", request.Email);
            return OperationResult<AuthResponse>.Ok(new AuthResponse(accessToken, refreshToken, expires));
        }

        public async Task<OperationResult<AuthResponse>> RefreshTokenAsync(RefreshRequest request)
        {
            logger.LogInformation("Attempting to refresh token");

            var principal = tokenService.GetPrincipalFromExpiredToken(request.AccessToken);
            var userId = principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (userId is null)
            {
                logger.LogWarning("Refresh failed: Invalid access token");
                return OperationResult<AuthResponse>.Fail("Invalid access token");
            }

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                logger.LogWarning("Refresh failed: User with ID {UserId} not found", userId);
                return OperationResult<AuthResponse>.Fail("User not found");
            }

            var storedToken = await context.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == request.RefreshToken && x.UserId == user.Id && !x.Revoked);

            if (storedToken == null)
            {
                logger.LogWarning("Refresh failed for user {Email}: Invalid or revoked refresh token", user.Email);
                return OperationResult<AuthResponse>.Fail("Invalid or expired refresh token");
            }

            if (storedToken.Expires < DateTime.UtcNow)
            {
                logger.LogWarning("Refresh failed for user {Email}: Refresh token expired", user.Email);
                return OperationResult<AuthResponse>.Fail("Invalid or expired refresh token");
            }

            logger.LogInformation("Refreshing tokens for user {Email}", user.Email);

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

            logger.LogInformation("Token refreshed successfully for user {Email}", user.Email);
            return OperationResult<AuthResponse>.Ok(new AuthResponse(newAccessToken, newRefreshToken, expires));
        }

        public async Task<OperationResult> RevokeRefreshTokenAsync(string refreshToken)
        {
            logger.LogInformation("Revocation requested for refresh token: {Token}", refreshToken);

            var token = await context.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == refreshToken);

            if (token == null)
            {
                logger.LogWarning("Revocation failed: Refresh token not found");
                return OperationResult.Fail("Refresh token not found");
            }

            if (token.Revoked)
            {
                logger.LogWarning("Revocation failed: Refresh token already revoked");
                return OperationResult.Fail("Refresh token already revoked");
            }

            token.Revoked = true;
            await context.SaveChangesAsync();

            logger.LogInformation("Refresh token {Token} revoked successfully", refreshToken);
            return OperationResult.Ok();
        }
    }
}
