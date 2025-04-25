using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Localization;
using AVP.AuthCore.API.Extensions;
using AVP.AuthCore.Application.Interfaces;
using AVP.AuthCore.Application.DTOs;
using AVP.AuthCore.Application.Resources;

namespace AVP.AuthCore.API.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController(IAuthService authService, ILogger<AuthController> logger, IStringLocalizer<ErrorMessages> localizer) : ControllerBase
    {
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var result = await authService.RegisterAsync(request);
            return result.ToActionResult(logger, localizer, HttpContext);
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var result = await authService.LoginAsync(request);
            return result.ToActionResult(logger, localizer, HttpContext);
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            var result = await authService.RefreshTokenAsync(request);
            return result.ToActionResult(logger, localizer, HttpContext);
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] RefreshRequest request)
        {
            var result = await authService.RevokeRefreshTokenAsync(request.RefreshToken);
            return result.ToActionResult(logger, localizer, HttpContext);
        }
    }
}
