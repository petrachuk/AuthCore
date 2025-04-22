using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using AVP.AuthCore.API.Extensions;
using AVP.AuthCore.Application.Interfaces;
using AVP.AuthCore.Application.DTOs;

namespace AVP.AuthCore.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController(IAuthService authService, ILogger<AuthController> logger) : ControllerBase
    {
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await authService.RegisterAsync(request);
            return result.ToActionResult(logger);
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await authService.LoginAsync(request);
            return result.ToActionResult(logger);
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await authService.RefreshTokenAsync(request);
            return result.ToActionResult(logger);
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] RefreshRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await authService.RevokeRefreshTokenAsync(request.RefreshToken);
            return result.ToActionResult(logger);
        }
    }
}
