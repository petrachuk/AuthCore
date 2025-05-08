using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using AVP.AuthCore.API.Extensions;
using AVP.AuthCore.Application.Interfaces;
using AVP.AuthCore.Application.DTOs;

namespace AVP.AuthCore.API.Controllers
{
    /// <summary>
    /// Controller for user authentication
    /// </summary>
    [ApiController]
    [Route("api/auth")]
    public class AuthController(IAuthService authService, ILogger<AuthController> logger) : ControllerBase
    {
        /// <summary>
        /// Registers a new user
        /// </summary>
        /// <param name="request">The registration details</param>
        /// <response code="201">User was successfully registered</response>
        /// <response code="409">A user with the provided credentials already exists</response>
        [AllowAnonymous]
        [HttpPost("register")]
        [ProducesResponseType(typeof(AuthResponse), 201)]
        [ProducesResponseType(409)]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var result = await authService.RegisterAsync(request);
            return result.ToActionResult(logger, HttpContext);
        }

        /// <summary>
        /// Authenticates a user and issues tokens
        /// </summary>
        /// <param name="request">The login credentials</param>
        /// <response code="200">User was successfully authenticated</response>
        /// <response code="401">Invalid username or password</response>
        [AllowAnonymous]
        [HttpPost("login")]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(401)]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var result = await authService.LoginAsync(request);
            return result.ToActionResult(logger, HttpContext);
        }

        /// <summary>
        /// Refreshes the access token
        /// </summary>
        /// <param name="request">Current access and refresh tokens</param>
        /// <response code="200">Access token was successfully refreshed</response>
        /// <response code="401">Invalid or expired access token</response>
        /// <response code="403">No valid refresh token found or token has been revoked</response>
        [AllowAnonymous]
        [HttpPost("refresh")]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(401)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            var result = await authService.RefreshTokenAsync(request);
            return result.ToActionResult(logger, HttpContext);
        }

        /// <summary>
        /// Revokes the refresh token and ends the session
        /// </summary>
        /// <param name="request">The refresh token to revoke</param>
        /// <response code="204">User successfully logged out. No content returned</response>
        /// <response code="401">Invalid or expired access token</response>
        [Authorize]
        [HttpPost("logout")]
        [ProducesResponseType(204)]
        [ProducesResponseType(401)]
        public async Task<IActionResult> Logout([FromBody] RefreshRequest request)
        {
            var result = await authService.RevokeRefreshTokenAsync(request.RefreshToken);
            return result.ToActionResult(logger, HttpContext);
        }
    }
}
