using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Http;
using Moq;
using AVP.AuthCore.Application.Common.Errors;
using AVP.AuthCore.Application.Common.Settings;
using AVP.AuthCore.Application.DTOs;
using AVP.AuthCore.Application.Interfaces;
using AVP.AuthCore.Application.Resources;
using AVP.AuthCore.Application.Services;
using AVP.AuthCore.Persistence.Entities;
using AVP.AuthCore.Persistence;

namespace AVP.AuthCore.Tests.Unit.Application.Services
{
    public class AuthServiceTests
    {
        private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
        private readonly Mock<RoleManager<IdentityRole>> _roleManagerMock;
        private readonly Mock<SignInManager<ApplicationUser>> _signInManagerMock;
        private readonly Mock<ITokenService> _tokenServiceMock;
        private readonly Mock<IOptionsMonitor<IdentitySettings>> _identitySettingsMock;
        private readonly Mock<IOptionsMonitor<JwtSettings>> _jwtSettingsMock;
        private readonly AuthDbContext _dbContext;
        private readonly AuthService _authService;

        public AuthServiceTests()
        {
            _userManagerMock = MockUserManager();
            _roleManagerMock = MockRoleManager();
            _signInManagerMock = MockSignInManager();
            _tokenServiceMock = new Mock<ITokenService>();
            _identitySettingsMock = new Mock<IOptionsMonitor<IdentitySettings>>();
            _jwtSettingsMock = new Mock<IOptionsMonitor<JwtSettings>>();
            Mock<ILogger<ErrorMessages>> loggerMock = new();

            var options = new DbContextOptionsBuilder<AuthDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;
            _dbContext = new AuthDbContext(options);

            _authService = new AuthService(
                _userManagerMock.Object,
                _roleManagerMock.Object,
                _signInManagerMock.Object,
                _tokenServiceMock.Object,
                _dbContext,
                _identitySettingsMock.Object,
                _jwtSettingsMock.Object,
                loggerMock.Object
            );
        }

        /// <summary>
        /// Успешная регистрация
        /// </summary>
        [Fact]
        public async Task RegisterAsync_Success_ReturnsOk()
        {
            // Arrange
            var request = new RegisterRequest { Email = "test@example.com", Password = "Password123!" };
            _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
                .ReturnsAsync(IdentityResult.Success);

            _roleManagerMock.Setup(x => x.RoleExistsAsync(It.IsAny<string>()))
                .ReturnsAsync(true);

            _userManagerMock.Setup(x => x.AddToRoleAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Success);

            _identitySettingsMock.Setup(x => x.CurrentValue)
                .Returns(new IdentitySettings { DefaultUserRole = "User" });

            _tokenServiceMock.Setup(x =>
                    x.GenerateAccessTokenAsync(It.IsAny<ApplicationUser>(), It.IsAny<IEnumerable<string>>()))
                .ReturnsAsync("access-token");

            _tokenServiceMock.Setup(x => x.GenerateRefreshTokenAsync())
                .ReturnsAsync("refresh-token");

            _jwtSettingsMock.Setup(x => x.CurrentValue)
                .Returns(new JwtSettings { RefreshTokenLifetimeDays = 7 });

            // Act
            var result = await _authService.RegisterAsync(request);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.Equal("access-token", result.Data?.AccessToken);
            Assert.Equal("refresh-token", result.Data?.RefreshToken);
        }

        /// <summary>
        /// Ошибка регистрации
        /// </summary>
        [Fact]
        public async Task RegisterAsync_Failure_ReturnsFail()
        {
            // Arrange
            var request = new RegisterRequest { Email = "fail@example.com", Password = "BadPassword" };
            var identityErrors = new List<IdentityError>
                { new IdentityError { Code = "DuplicateUserName", Description = "User already exists." } };

            _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
                .ReturnsAsync(IdentityResult.Failed(identityErrors.ToArray()));

            // Act
            var result = await _authService.RegisterAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.RegistrationFailed, result.Error);
            // Убедимся, что RawMessages не равен null перед вызовом Assert.Contains
            Assert.NotNull(result.RawMessages);
            Assert.Contains("User already exists.", result.RawMessages!);

        }

        /// <summary>
        /// Успешный логин
        /// </summary>
        [Fact]
        public async Task LoginAsync_Success_ReturnsOk()
        {
            // Arrange
            var request = new LoginRequest { Email = "login@example.com", Password = "Password123!" };
            var user = new ApplicationUser { Id = "userId", Email = request.Email };

            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync(user);

            _signInManagerMock.Setup(x => x.CheckPasswordSignInAsync(user, request.Password, false))
                .ReturnsAsync(SignInResult.Success);

            _userManagerMock.Setup(x => x.GetRolesAsync(user))
                .ReturnsAsync(new List<string> { "User" });

            _tokenServiceMock.Setup(x => x.GenerateAccessTokenAsync(user, It.IsAny<IEnumerable<string>>()))
                .ReturnsAsync("access-token");

            _tokenServiceMock.Setup(x => x.GenerateRefreshTokenAsync())
                .ReturnsAsync("refresh-token");

            // Act
            var result = await _authService.LoginAsync(request);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.Equal("access-token", result.Data?.AccessToken);
        }

        /// <summary>
        /// Ошибка логина
        /// </summary>
        [Fact]
        public async Task LoginAsync_UserNotFound_ReturnsFail()
        {
            // Arrange
            var request = new LoginRequest { Email = "notfound@example.com", Password = "Password123!" };
            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync((ApplicationUser?)null);

            // Act
            var result = await _authService.LoginAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.InvalidCredentials, result.Error);
        }

        [Fact]
        public async Task RefreshTokenAsync_InvalidAccessToken_ReturnsFail()
        {
            // Arrange
            var request = new RefreshRequest { AccessToken = "invalid", RefreshToken = "refresh-token" };
            _tokenServiceMock.Setup(x => x.GetPrincipalFromExpiredToken(request.AccessToken))
                .Returns((ClaimsPrincipal?)null);

            // Act
            var result = await _authService.RefreshTokenAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.InvalidAccessToken, result.Error);
        }

        [Fact]
        public async Task RefreshTokenAsync_Success_ReturnsOk()
        {
            // Arrange
            var user = new ApplicationUser { Id = "userId", Email = "test@example.com" };
            var request = new RefreshRequest { AccessToken = "access-token", RefreshToken = "refresh-token" };

            var claims = new List<Claim> { new Claim(ClaimTypes.NameIdentifier, user.Id) };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));

            _tokenServiceMock.Setup(x => x.GetPrincipalFromExpiredToken(request.AccessToken))
                .Returns(principal);

            _userManagerMock.Setup(x => x.FindByIdAsync(user.Id))
                .ReturnsAsync(user);

            _dbContext.RefreshTokens.Add(new RefreshToken
            {
                Token = request.RefreshToken,
                UserId = user.Id,
                Expires = DateTime.UtcNow.AddMinutes(5)
            });
            await _dbContext.SaveChangesAsync();

            _tokenServiceMock.Setup(x => x.GenerateRefreshTokenAsync())
                .ReturnsAsync("new-refresh-token");

            _userManagerMock.Setup(x => x.GetRolesAsync(user))
                .ReturnsAsync(new List<string> { "User" });

            _tokenServiceMock.Setup(x => x.GenerateAccessTokenAsync(user, It.IsAny<IEnumerable<string>>()))
                .ReturnsAsync("new-access-token");

            // Act
            var result = await _authService.RefreshTokenAsync(request);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.Equal("new-access-token", result.Data?.AccessToken);
            Assert.Equal("new-refresh-token", result.Data?.RefreshToken);
        }

        #region Helpers

        private static Mock<UserManager<ApplicationUser>> MockUserManager()
        {
            var store = new Mock<IUserStore<ApplicationUser>>();
            return new Mock<UserManager<ApplicationUser>>(
                store.Object,
                new Mock<IOptions<IdentityOptions>>().Object,
                new Mock<IPasswordHasher<ApplicationUser>>().Object,
                Array.Empty<IUserValidator<ApplicationUser>>(),
                Array.Empty<IPasswordValidator<ApplicationUser>>(),
                new Mock<ILookupNormalizer>().Object,
                new Mock<IdentityErrorDescriber>().Object,
                new Mock<IServiceProvider>().Object,
                new Mock<ILogger<UserManager<ApplicationUser>>>().Object
            );
        }

        private static Mock<RoleManager<IdentityRole>> MockRoleManager()
        {
            var store = new Mock<IRoleStore<IdentityRole>>();
            return new Mock<RoleManager<IdentityRole>>(
                store.Object,
                new List<IRoleValidator<IdentityRole>>(),
                new Mock<ILookupNormalizer>().Object,
                new Mock<IdentityErrorDescriber>().Object,
                new Mock<ILogger<RoleManager<IdentityRole>>>().Object
            );
        }

        private static Mock<SignInManager<ApplicationUser>> MockSignInManager()
        {
            var userManager = MockUserManager();
            var contextAccessor = new Mock<IHttpContextAccessor>();
            var claimsFactory = new Mock<IUserClaimsPrincipalFactory<ApplicationUser>>();
            var options = new Mock<IOptions<IdentityOptions>>();
            var logger = new Mock<ILogger<SignInManager<ApplicationUser>>>();

            return new Mock<SignInManager<ApplicationUser>>(
                userManager.Object,
                contextAccessor.Object,
                claimsFactory.Object,
                options.Object,
                logger.Object,
                null!,
                null!
            );
        }

        [Fact]
        public async Task RefreshTokenAsync_TokenNotFound_ReturnsFail()
        {
            // Arrange
            var user = new ApplicationUser { Id = "userId", Email = "test@example.com" };
            var request = new RefreshRequest { AccessToken = "access-token", RefreshToken = "invalid-refresh-token" };

            var claims = new List<Claim> { new Claim(ClaimTypes.NameIdentifier, user.Id) };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));

            _tokenServiceMock.Setup(x => x.GetPrincipalFromExpiredToken(request.AccessToken))
                .Returns(principal);

            _userManagerMock.Setup(x => x.FindByIdAsync(user.Id))
                .ReturnsAsync(user);

            // В БД нет токена с таким значением
            // _dbContext.RefreshTokens пуст

            // Act
            var result = await _authService.RefreshTokenAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.RefreshTokenNotFound, result.Error);
        }

        [Fact]
        public async Task RefreshTokenAsync_TokenExpired_ReturnsFail()
        {
            // Arrange
            var user = new ApplicationUser { Id = "userId", Email = "test@example.com" };
            var request = new RefreshRequest { AccessToken = "access-token", RefreshToken = "refresh-token" };

            var claims = new List<Claim> { new Claim(ClaimTypes.NameIdentifier, user.Id) };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));

            _tokenServiceMock.Setup(x => x.GetPrincipalFromExpiredToken(request.AccessToken))
                .Returns(principal);

            _userManagerMock.Setup(x => x.FindByIdAsync(user.Id))
                .ReturnsAsync(user);

            _dbContext.RefreshTokens.Add(new RefreshToken
            {
                Token = request.RefreshToken,
                UserId = user.Id,
                Expires = DateTime.UtcNow.AddMinutes(-5) // просроченный токен
            });
            await _dbContext.SaveChangesAsync();

            // Act
            var result = await _authService.RefreshTokenAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.RefreshTokenExpired, result.Error);
        }

        [Fact]
        public async Task RefreshTokenAsync_TokenBelongsToAnotherUser_ReturnsFail()
        {
            // Arrange
            var user = new ApplicationUser { Id = "userId", Email = "test@example.com" };
            var request = new RefreshRequest { AccessToken = "access-token", RefreshToken = "refresh-token" };

            var claims = new List<Claim> { new Claim(ClaimTypes.NameIdentifier, user.Id) };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));

            _tokenServiceMock.Setup(x => x.GetPrincipalFromExpiredToken(request.AccessToken))
                .Returns(principal);

            _userManagerMock.Setup(x => x.FindByIdAsync(user.Id))
                .ReturnsAsync(user);

            _dbContext.RefreshTokens.Add(new RefreshToken
            {
                Token = request.RefreshToken,
                UserId = "anotherUserId", // чужой токен
                Expires = DateTime.UtcNow.AddDays(1) // гарантированно живой токен
            });
            await _dbContext.SaveChangesAsync();

            // Act
            var result = await _authService.RefreshTokenAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.RefreshTokenInvalid, result.Error);
        }

        [Fact]
        public async Task RefreshTokenAsync_UserNotFound_ReturnsFail()
        {
            // Arrange
            var request = new RefreshRequest { AccessToken = "access-token", RefreshToken = "refresh-token" };

            var claims = new List<Claim> { new Claim(ClaimTypes.NameIdentifier, "userId") };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));

            _tokenServiceMock.Setup(x => x.GetPrincipalFromExpiredToken(request.AccessToken))
                .Returns(principal);

            _userManagerMock.Setup(x => x.FindByIdAsync("userId"))
                .ReturnsAsync((ApplicationUser?)null); // Пользователь не найден

            // Act
            var result = await _authService.RefreshTokenAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.UserNotFound, result.Error);
        }

        #endregion
    }
}