using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AuthCore.API.Extensions;
using AuthCore.Application.DTOs;
using AuthCore.Application.Interfaces;


namespace AuthCore.API.Controllers
{
    /// <summary>
    /// Controller for user authentication
    /// </summary>
    [ApiController]
    [Route("api/account")]
    public class AccountController(IAccountService accountService, ILogger<AccountController> logger) : ControllerBase
    {
        /// <summary>
        /// Sends an email confirmation code to the user
        /// </summary>
        /// <param name="request">The email to send the confirmation code to</param>
        /// <response code="204">Confirmation email sent successfully</response>
        /// <response code="404">User not found</response>
        [AllowAnonymous]
        [HttpPost("verification/send")]
        [ProducesResponseType(204)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> SendConfirmationCode([FromBody] SendConfirmationRequest request)
        {
            var result = await accountService.SendConfirmationCodeAsync(request);
            return result.ToActionResult(logger, HttpContext);
        }

        /// <summary>
        /// Confirms a user's email address
        /// </summary>
        /// <param name="request">The email address and confirmation code</param>
        /// <response code="204">Email confirmed successfully</response>
        /// <response code="400">Invalid or expired confirmation code</response>
        /// <response code="404">User not found</response>
        [AllowAnonymous]
        [HttpPost("verification/confirm")]
        [ProducesResponseType(204)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> VerifyIdentity([FromBody] VerificationRequest request)
        {
            var result = await accountService.VerifyIdentityAsync(request);
            return result.ToActionResult(logger, HttpContext);
        }

        /// <summary>
        /// Initiates the password recovery process
        /// </summary>
        /// <param name="request">The email address for password recovery</param>
        /// <response code="204">Recovery email sent successfully</response>
        [AllowAnonymous]
        [HttpPost("password/request-reset")]
        [ProducesResponseType(204)]
        public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequest request)
        {
            var result = await accountService.SendPasswordResetCodeAsync(request);
            return result.ToActionResult(logger, HttpContext);
        }

        /// <summary>
        /// Resets a user's password using a recovery code
        /// </summary>
        /// <param name="request">The email, reset code and new password</param>
        /// <response code="204">Password reset successfully</response>
        /// <response code="400">Invalid or expired reset code</response>
        /// <response code="404">User not found</response>
        [AllowAnonymous]
        [HttpPost("password/reset")]
        [ProducesResponseType(204)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            var result = await accountService.ResetPasswordAsync(request);
            return result.ToActionResult(logger, HttpContext);
        }
    }
}
