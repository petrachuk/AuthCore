using AuthCore.Abstractions.Interfaces;
using AuthCore.Abstractions.Models;
using AuthCore.Abstractions.Settings;
using AuthCore.Application.Common.Errors;
using AuthCore.Application.Common.Results;
using AuthCore.Application.DTOs;
using AuthCore.Application.Interfaces;
using AuthCore.Persistence.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;

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
            logger.LogInformation("Registration attempt with {IdentityType}: {Identifier}", request.IdentityType, request.Identifier);

            // var user = new ApplicationUser { UserName = request.Email, Email = request.Email };
            var user = new ApplicationUser();

            switch (request.IdentityType)
            {
                case IdentityType.Email:
                    user.Email = request.Identifier;
                    user.UserName = request.Identifier; // Используем email как имя пользователя
                    break;

                case IdentityType.Phone:
                    user.PhoneNumber = request.Identifier;
                    user.UserName = $"phone_{request.Identifier}"; // Префикс для уникальности
                    break;

                case IdentityType.Telegram:
                    if (long.TryParse(request.Identifier, out var telegramId))
                    {
                        user.TelegramId = telegramId;
                        user.UserName = $"telegram_{telegramId}";
                    }
                    else
                    {
                        logger.LogWarning("Telegram identifier is not numeric: {Identifier}", request.Identifier);
                        user.TelegramId = null; // Or handle as appropriate for your application
                        user.UserName = $"telegram_{request.Identifier}";
                    }
                    break;

                case IdentityType.WhatsApp:
                    user.WhatsAppId = request.Identifier;
                    user.UserName = $"whatsapp_{request.Identifier}";
                    break;

                default:
                    return OperationResult<AuthResponse>.Fail(ErrorCode.InvalidRequest);
            }

            // Для email и телефона требуем пароль, для мессенджеров - необязательно
            IdentityResult result;

            if (request.IdentityType is IdentityType.Email or IdentityType.Phone)
            {
                if (string.IsNullOrEmpty(request.Password))
                {
                    return OperationResult<AuthResponse>.Fail(ErrorCode.ValidationFailed);
                }

                result = await userManager.CreateAsync(user, request.Password);
            }
            else
            {
                // Для мессенджеров генерируем случайный пароль если он не был предоставлен
                var password = !string.IsNullOrEmpty(request.Password)
                    ? request.Password
                    : Guid.NewGuid().ToString("N") + "!Aa1";

                result = await userManager.CreateAsync(user, password);
            }

            if (!result.Succeeded)
            {
                logger.LogWarning("Registration failed for {IdentityType}: {Identifier} with errors: {Errors}",
                    request.IdentityType, request.Identifier, result.Errors.Select(e => e.Description));

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

            logger.LogInformation("User with {IdentityType}: {Identifier} registered successfully",
                request.IdentityType, request.Identifier);

            return OperationResult<AuthResponse>.Ok(new AuthResponse(accessToken, refreshToken, expires), isCreated: true);
        }

        public async Task<OperationResult<AuthResponse>> LoginAsync(LoginRequest request)
        {
            logger.LogInformation("Login attempt with {IdentityType}: {Identifier}",
                request.IdentityType, request.Identifier);

            // Находим пользователя в зависимости от типа идентификатора
            ApplicationUser? user = null;

            switch (request.IdentityType)
            {
                case IdentityType.Email:
                    user = await userManager.FindByEmailAsync(request.Identifier);
                    break;

                case IdentityType.Phone:
                    user = await userManager.Users.FirstOrDefaultAsync(u => u.PhoneNumber == request.Identifier);
                    break;

                case IdentityType.Telegram:
                    user = await userManager.Users.FirstOrDefaultAsync(u => u.UserName == $"telegram_{request.Identifier}");
                    break;

                case IdentityType.WhatsApp:
                    user = await userManager.Users.FirstOrDefaultAsync(u => u.UserName == $"whatsapp_{request.Identifier}");
                    break;
            }

            if (user == null)
            {
                logger.LogWarning("Login failed for {IdentityType}: {Identifier} with errors: User not found",
                    request.IdentityType, request.Identifier);
                return OperationResult<AuthResponse>.Fail(ErrorCode.InvalidCredentials);
            }

            // Для разных типов идентификации - разные способы проверки
            var authSuccess = false;

            if (request.IdentityType is IdentityType.Email or IdentityType.Phone)
            {
                // Для email и телефона требуем стандартную аутентификацию с паролем
                if (string.IsNullOrEmpty(request.Password))
                {
                    return OperationResult<AuthResponse>.Fail(ErrorCode.InvalidCredentials);
                }

                var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, false);
                authSuccess = result.Succeeded;
            }
            else if (request.IdentityType is IdentityType.Telegram or IdentityType.WhatsApp)
            {
                // Для мессенджеров можно реализовать отдельную логику проверки
                // Например, проверка через внешний API, токен подтверждения и т.д.
                // Здесь для примера предполагаем, что проверка уже выполнена
                authSuccess = true;
            }

            if (!authSuccess)
            {
                logger.LogWarning("Login failed for {IdentityType}: {Identifier} with errors: Invalid credentials",
                    request.IdentityType, request.Identifier);
                return OperationResult<AuthResponse>.Fail(ErrorCode.InvalidCredentials);
            }

            var roles = await userManager.GetRolesAsync(user);

            var accessToken = await tokenService.GenerateAccessTokenAsync(user, roles);
            var refreshToken = await tokenService.GenerateRefreshTokenAsync();
            var expires = DateTime.UtcNow.AddDays(jwtSettingsMonitor.CurrentValue.RefreshTokenLifetimeDays);

            await refreshTokenStore.SaveRefreshTokenAsync(new RefreshTokenInfo
                { UserId = user.Id, Token = refreshToken, Expires = expires });

            logger.LogInformation("User with {IdentityType}: {Identifier} logged in successfully",
                request.IdentityType, request.Identifier);

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
