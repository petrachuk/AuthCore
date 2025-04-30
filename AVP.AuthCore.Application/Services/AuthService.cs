using System.Security.Claims;
using AVP.AuthCore.Application.Common.Errors;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using AVP.AuthCore.Application.Interfaces;
using AVP.AuthCore.Application.DTOs;
using AVP.AuthCore.Persistence;
using AVP.AuthCore.Persistence.Entities;
using AVP.AuthCore.Application.Common.Results;
using AVP.AuthCore.Application.Resources;
using AVP.AuthCore.Application.Common.Settings;
using Microsoft.Extensions.Options;

namespace AVP.AuthCore.Application.Services
{
    public class AuthService(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        SignInManager<ApplicationUser> signInManager,
        ITokenService tokenService,
        AuthDbContext context,
        IOptionsMonitor<IdentitySettings> identitySettingsMonitor,
        IOptionsMonitor<JwtSettings> jwtSettingsMonitor,
        ILogger<ErrorMessages> logger) : IAuthService
    {
        public async Task<OperationResult<AuthResponse>> RegisterAsync(RegisterRequest request)
        {
            logger.LogInformation("Registration attempt for {Email}", request.Email);

            var user = new ApplicationUser { UserName = request.Email, Email = request.Email };
            var result = await userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                logger.LogWarning("Registration failed for {Email} with errors: {Errors}", request.Email, result.Errors.Select(e => e.Description));

                var details = result.Errors
                    .Select(e => Enum.TryParse<ErrorCode>(e.Code, out var errorCode) ? errorCode : ErrorCode.Unknown);

                var messages = result.Errors
                    .Select(e => e.Description)
                    .ToList();

                return OperationResult<AuthResponse>.Fail(ErrorCode.RegistrationFailed, details, messages);
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

            context.RefreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                Expires = expires,
                UserId = user.Id
            });

            await context.SaveChangesAsync();

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
                return OperationResult<AuthResponse>.Fail(ErrorCode.InvalidAccessToken);
            }

            var user = await userManager.FindByIdAsync(userId);
            if (user is null)
            {
                logger.LogWarning("Refresh failed: User with ID {UserId} not found", userId);
                return OperationResult<AuthResponse>.Fail(ErrorCode.UserNotFound);
            }

            var storedToken = await context.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == request.RefreshToken && !x.Revoked);

            switch (storedToken)
            {
                case null:
                    logger.LogWarning("Refresh failed: Refresh token not found for user {Email}", user.Email);
                    return OperationResult<AuthResponse>.Fail(ErrorCode.RefreshTokenNotFound);

                case { UserId: not null, Expires: var expiry } when expiry < DateTime.UtcNow:
                    logger.LogWarning("Refresh failed: Expired refresh token for user {Email}", user.Email);
                    return OperationResult<AuthResponse>.Fail(ErrorCode.RefreshTokenExpired);

                case { UserId: not null, UserId: var tokenUserId } when tokenUserId != user.Id:
                    logger.LogWarning("Refresh failed: Refresh token belongs to another user {Email}", user.Email);
                    return OperationResult<AuthResponse>.Fail(ErrorCode.RefreshTokenInvalid);
            }

            logger.LogInformation("Refreshing tokens for user {Email}", user.Email);

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

            var roles = await userManager.GetRolesAsync(user);
            var newAccessToken = await tokenService.GenerateAccessTokenAsync(user, roles);

            logger.LogInformation("Token refreshed successfully for user {Email}", user.Email);
            return OperationResult<AuthResponse>.Ok(new AuthResponse(newAccessToken, newRefreshToken, expires));
        }

        public async Task<OperationResult> RevokeRefreshTokenAsync(string refreshToken)
        {
            logger.LogInformation("Revocation requested for refresh token: {Token}", refreshToken);

            var token = await context.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == refreshToken);

            if (token is null)
            {
                logger.LogWarning("Revocation failed: Refresh token not found");
                return OperationResult.Fail(ErrorCode.RefreshTokenNotFound);
            }

            if (token.Revoked)
            {
                logger.LogWarning("Revocation failed: Refresh token already revoked");
                return OperationResult.Fail(ErrorCode.RefreshTokenAlreadyRevoked);
            }

            token.Revoked = true;
            await context.SaveChangesAsync();

            logger.LogInformation("Refresh token {Token} revoked successfully", refreshToken);
            return OperationResult.Ok();
        }
    }
}
