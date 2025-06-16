using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using AuthCore.Application.Common.Errors;
using AuthCore.Application.Common.Results;
using AuthCore.Abstractions.Settings;
using AuthCore.Application.DTOs;
using AuthCore.Application.Interfaces;
using AuthCore.Persistence.Entities;
using AuthCore.Abstractions.Interfaces;
using AuthCore.Abstractions.Models;

namespace AuthCore.Application.Services
{
    public class AuthService(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        SignInManager<ApplicationUser> signInManager,
        ITokenService tokenService,
        IRefreshTokenStore refreshTokenStore,
        IOptionsMonitor<IdentitySettings> identitySettingsMonitor,
        IOptionsMonitor<JwtSettings> jwtSettingsMonitor,
        ILogger<AuthService> logger) : IAuthService
    {
        public async Task<OperationResult<AuthResponse>> RegisterAsync(RegisterRequest request)
        {
            logger.LogInformation("Registration attempt for {Email}", request.Email);

            var user = new ApplicationUser { UserName = request.Email, Email = request.Email };
            var result = await userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                logger.LogWarning("Registration failed for {Email} with errors: {Errors}", request.Email, result.Errors.Select(e => e.Description));

                return OperationResult<AuthResponse>.Fail(
                    result.Errors.FirstOrDefault()?.Code == "DuplicateUserName"
                        ? ErrorCode.UserAlreadyExists
                        : ErrorCode.RegistrationFailed, result.Errors);
            }

            // Добавить роль по умолчанию
            var defaultRole = identitySettingsMonitor.CurrentValue.DefaultUserRole;

            // Убедиться, что такая роль есть
            if (!await roleManager.RoleExistsAsync(defaultRole))
                await roleManager.CreateAsync(new IdentityRole(defaultRole));

            // Назначить роль
            await userManager.AddToRoleAsync(user, defaultRole);

            var accessToken = await tokenService.GenerateAccessTokenAsync(user, [ defaultRole ]);
            var refreshToken = await tokenService.GenerateRefreshTokenAsync();
            var expires = DateTime.UtcNow.AddDays(jwtSettingsMonitor.CurrentValue.RefreshTokenLifetimeDays);

            await refreshTokenStore.SaveRefreshTokenAsync(new RefreshTokenInfo
                { UserId = user.Id, Token = refreshToken, Expires = expires });

            logger.LogInformation("User {Email} registered successfully", request.Email);
            return OperationResult<AuthResponse>.Ok(new AuthResponse(accessToken, refreshToken, expires), isCreated: true);
        }

        public async Task<OperationResult<AuthResponse>> LoginAsync(LoginRequest request)
        {
            logger.LogInformation("Login attempt for {Email}", request.Email);

            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                logger.LogWarning("Login failed for {Email} with errors: Invalid credentials", request.Email);
                return OperationResult<AuthResponse>.Fail(ErrorCode.InvalidCredentials);
            }

            var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            if (!result.Succeeded)
            {
                logger.LogWarning("Login failed for {Email} with errors: Invalid credentials", request.Email);
                return OperationResult<AuthResponse>.Fail(ErrorCode.InvalidCredentials);
            }

            var roles = await userManager.GetRolesAsync(user);

            var accessToken = await tokenService.GenerateAccessTokenAsync(user, roles);
            var refreshToken = await tokenService.GenerateRefreshTokenAsync();
            var expires = DateTime.UtcNow.AddDays(jwtSettingsMonitor.CurrentValue.RefreshTokenLifetimeDays);

            await refreshTokenStore.SaveRefreshTokenAsync(new RefreshTokenInfo
                { UserId = user.Id, Token = refreshToken, Expires = expires });

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
                return OperationResult<AuthResponse>.Fail(ErrorCode.InvalidAccessToken);
            }

            var user = await userManager.FindByIdAsync(userId);
            if (user is null)
            {
                logger.LogWarning("Refresh failed: User with ID {UserId} not found", userId);
                return OperationResult<AuthResponse>.Fail(ErrorCode.UserNotFound);
            }

            var storedRefreshToken = await refreshTokenStore.GetRefreshTokenAsync(request.RefreshToken);

            switch (storedRefreshToken)
            {
                case null:
                    logger.LogWarning("Refresh failed: Refresh token not found for user {Email}", user.Email);
                    return OperationResult<AuthResponse>.Fail(ErrorCode.RefreshTokenNotFound);

                case { Expires: var expiry } when expiry < DateTime.UtcNow:
                    logger.LogWarning("Refresh failed: Expired refresh token for user {Email}", user.Email);
                    return OperationResult<AuthResponse>.Fail(ErrorCode.RefreshTokenExpired);

                case { UserId: var tokenUserId } when tokenUserId != user.Id:
                    logger.LogWarning("Refresh failed: Refresh token belongs to another user {Email}", user.Email);
                    return OperationResult<AuthResponse>.Fail(ErrorCode.RefreshTokenInvalid);
            }

            logger.LogInformation("Refreshing tokens for user {Email}", user.Email);

            var newRefreshToken = await tokenService.GenerateRefreshTokenAsync();
            var expires = DateTime.UtcNow.AddDays(7);

            await refreshTokenStore.SaveRefreshTokenAsync(new RefreshTokenInfo
                { UserId = user.Id, Token = newRefreshToken, Expires = expires });
            await refreshTokenStore.DeleteRefreshTokenAsync(storedRefreshToken.Token);

            var roles = await userManager.GetRolesAsync(user);
            var newAccessToken = await tokenService.GenerateAccessTokenAsync(user, roles);

            logger.LogInformation("Token refreshed successfully for user {Email}", user.Email);
            return OperationResult<AuthResponse>.Ok(new AuthResponse(newAccessToken, newRefreshToken, expires));
        }

        public async Task<OperationResult> RevokeRefreshTokenAsync(string refreshToken)
        {
            logger.LogInformation("Revocation requested for refresh token: {Token}", refreshToken);

            var storedRefreshToken = await refreshTokenStore.GetRefreshTokenAsync(refreshToken);

            if (storedRefreshToken is null)
            {
                logger.LogWarning("Revocation failed: Refresh token not found");
                return OperationResult.Fail(ErrorCode.RefreshTokenNotFound);
            }

            await refreshTokenStore.DeleteRefreshTokenAsync(storedRefreshToken.Token);

            logger.LogInformation("Refresh token {Token} revoked successfully", refreshToken);
            return OperationResult.Ok();
        }
    }
}
