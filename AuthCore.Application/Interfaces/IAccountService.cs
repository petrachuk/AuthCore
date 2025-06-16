using AuthCore.Application.Common.Results;
using AuthCore.Application.DTOs;

namespace AuthCore.Application.Interfaces
{
    public interface IAccountService
    {
        Task<OperationResult> SendConfirmationCodeAsync(SendConfirmationRequest request);
        Task<OperationResult> VerifyIdentityAsync(VerificationRequest request);
        Task<OperationResult> SendPasswordResetCodeAsync(PasswordResetRequest request);
        Task<OperationResult> ResetPasswordAsync(ResetPasswordRequest request);
    }
}
