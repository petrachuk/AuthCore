using Microsoft.AspNetCore.Mvc;
using AVP.AuthCore.Application.Interfaces;
using AVP.AuthCore.Application.DTOs;
using Microsoft.AspNetCore.Authorization;

namespace AVP.AuthCore.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid) return BadRequest();

            var result = await authService.RegisterAsync(request);

            return Ok(result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid) return BadRequest();

            var result = await authService.LoginAsync(request);

            if (!result.IsSuccessful) return Unauthorized(result);

            return Ok(result);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            if (!ModelState.IsValid) return BadRequest();

            var result = await authService.RefreshTokenAsync(request);

            if (!result.IsSuccessful) return Unauthorized(result);

            return Ok(result);
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] RefreshRequest request)
        {
            if (!ModelState.IsValid) return BadRequest();

            await authService.RevokeRefreshTokenAsync(request.RefreshToken);

            return NoContent();
        }
    }
}
