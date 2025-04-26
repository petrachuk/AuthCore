using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Localization;
using AVP.AuthCore.API.Extensions;
using AVP.AuthCore.Application.Interfaces;
using AVP.AuthCore.Application.DTOs;
using AVP.AuthCore.Application.Resources;

namespace AVP.AuthCore.API.Controllers
{
    /// <summary>
    /// Controller for user authentication
    /// </summary>
    [ApiController]
    [Route("api/auth")]
    public class AuthController(IAuthService authService, ILogger<AuthController> logger, IStringLocalizer<ErrorMessages> localizer) : ControllerBase
    {
        /// <summary>
        /// Registers a new user
        /// </summary>
        /// <param name="request">The registration details</param>
        /// <returns>The registration result</returns>
        [AllowAnonymous]
        [HttpPost("register")]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(500)]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var result = await authService.RegisterAsync(request);
            return result.ToActionResult(logger, localizer, HttpContext);
        }

        /// <summary>
        /// Authenticates a user and issues tokens
        /// </summary>
        /// <param name="request">The login credentials</param>
        /// <returns>The authentication result with tokens</returns>
        [AllowAnonymous]
        [HttpPost("login")]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        [ProducesResponseType(500)]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var result = await authService.LoginAsync(request);
            return result.ToActionResult(logger, localizer, HttpContext);
        }

        /// <summary>
        /// Refreshes the access token
        /// </summary>
        /// <param name="request">Current access and refresh tokens</param>
        /// <returns>The new pair of tokens</returns>
        [AllowAnonymous]
        [HttpPost("refresh")]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        [ProducesResponseType(500)]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            var result = await authService.RefreshTokenAsync(request);
            return result.ToActionResult(logger, localizer, HttpContext);
        }

        /// <summary>
        /// Revokes the refresh token and ends the session
        /// </summary>
        /// <param name="request">The refresh token to revoke</param>
        /// <returns>The logout result</returns>
        [Authorize]
        [HttpPost("logout")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        [ProducesResponseType(500)]
        public async Task<IActionResult> Logout([FromBody] RefreshRequest request)
        {
            var result = await authService.RevokeRefreshTokenAsync(request.RefreshToken);
            return result.ToActionResult(logger, localizer, HttpContext);
        }
    }
}
