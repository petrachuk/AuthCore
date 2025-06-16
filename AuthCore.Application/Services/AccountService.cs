using AuthCore.Abstractions.Interfaces;
using AuthCore.Abstractions.Models;
using AuthCore.Application.Common.Errors;
using AuthCore.Application.Common.Results;
using AuthCore.Application.DTOs;
using AuthCore.Application.Interfaces;
using AuthCore.Persistence.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace AuthCore.Application.Services
{
    public class AccountService(
        UserManager<ApplicationUser> userManager,
        INotificationSender notificationService,
        ILogger<AccountService> logger) : IAccountService
    {
        public async Task<OperationResult> SendConfirmationCodeAsync(SendConfirmationRequest request)
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                logger.LogWarning("Email confirmation requested for non-existent user: {Email}", request.Email);
                return OperationResult.Fail(ErrorCode.UserNotFound);
            }

            if (await userManager.IsEmailConfirmedAsync(user))
            {
                logger.LogInformation("Email already confirmed for user: {Email}", request.Email);
                // Возвращаем успех вместо ошибки, так как повторное подтверждение не критично
                return OperationResult.Ok();
            }

            var token = await userManager.GenerateEmailConfirmationTokenAsync(user);

            var message = new NotificationMessage
            {
                Recipient = user.Email ?? string.Empty,
                Subject = "Confirm your email address",
                Body = $"Please confirm your account by using this code: {token}"
            };

            await notificationService.SendAsync(message, CancellationToken.None);

            logger.LogInformation("Email confirmation sent to: {Email}", request.Email);
            return OperationResult.Ok();
        }

        public async Task<OperationResult> VerifyIdentityAsync(VerificationRequest request)
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                logger.LogWarning("Email confirmation attempted for non-existent user: {Email}", request.Email);
                return OperationResult.Fail(ErrorCode.UserNotFound);
            }

            if (await userManager.IsEmailConfirmedAsync(user))
            {
                logger.LogInformation("Email already confirmed for user: {Email}", request.Email);
                return OperationResult.Fail(ErrorCode.EmailAlreadyConfirmed);
            }

            var result = await userManager.ConfirmEmailAsync(user, request.ConfirmationCode);

            if (!result.Succeeded)
            {
                logger.LogWarning("Email confirmation failed for user {Email}: {Errors}",
                    request.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
                return OperationResult.Fail(ErrorCode.InvalidEmailConfirmationToken, result.Errors);
            }

            logger.LogInformation("Email confirmed successfully for user: {Email}", request.Email);
            return OperationResult.Ok();
        }

        public async Task<OperationResult> SendPasswordResetCodeAsync(PasswordResetRequest request)
        {
            // For security reasons, always return success even if user not found
            // This prevents user enumeration attacks
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                logger.LogInformation("Password reset requested for non-existent user: {Email}", request.Email);
                return OperationResult.Ok();
            }

            if (!await userManager.IsEmailConfirmedAsync(user))
            {
                logger.LogInformation("Password reset requested for unconfirmed email: {Email}", request.Email);
                return OperationResult.Ok();
            }

            var token = await userManager.GeneratePasswordResetTokenAsync(user);

            var message = new NotificationMessage
            {
                Recipient = user.Email ?? string.Empty,
                Subject = "Reset your password",
                Body = $"Please reset your password by using this code: {token}"
            };

            await notificationService.SendAsync(message, CancellationToken.None);

            logger.LogInformation("Password reset email sent to: {Email}", request.Email);
            return OperationResult.Ok();
        }

        public async Task<OperationResult> ResetPasswordAsync(ResetPasswordRequest request)
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                logger.LogWarning("Password reset attempted for non-existent user: {Email}", request.Email);
                return OperationResult.Fail(ErrorCode.UserNotFound);
            }

            if (!await userManager.IsEmailConfirmedAsync(user))
            {
                logger.LogWarning("Password reset attempted for unconfirmed email: {Email}", request.Email);
                return OperationResult.Fail(ErrorCode.EmailNotConfirmed);
            }

            var result = await userManager.ResetPasswordAsync(user, request.ResetCode, request.NewPassword);

            if (!result.Succeeded)
            {
                logger.LogWarning("Password reset failed for user {Email}: {Errors}",
                    request.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
                return OperationResult.Fail(ErrorCode.InvalidPasswordResetToken, result.Errors);
            }

            logger.LogInformation("Password reset successfully for user: {Email}", request.Email);
            return OperationResult.Ok();
        }
    }
}
