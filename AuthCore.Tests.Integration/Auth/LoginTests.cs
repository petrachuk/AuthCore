using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using FluentAssertions;
using AuthCore.Tests.Integration.Fixtures;
using AuthCore.API;
using AuthCore.Application.DTOs;
using AuthCore.Persistence.Entities;

namespace AuthCore.Tests.Integration.Auth
{
    public class LoginTests(CustomWebApplicationFactory<Program> factory)
        : IClassFixture<CustomWebApplicationFactory<Program>>
    {
        private readonly HttpClient _client = factory.CreateClient();

        [Fact]
        public async Task Login_ShouldReturn200AndTokens_WhenCredentialsAreValid()
        {
            // Arrange
            var loginRequest = new LoginRequest
            {
                IdentityType = IdentityType.Email,
                Identifier = "testuser@example.com",
                Password = "ValidPassword123!"
            };

            // Добавляем пользователя в базу данных
            using (var scope = factory.Services.CreateScope())
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

                var user = new ApplicationUser { UserName = loginRequest.Identifier, Email = loginRequest.Identifier };
                await userManager.CreateAsync(user, loginRequest.Password);
            }

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
            Assert.NotNull(authResponse);
            Assert.False(string.IsNullOrEmpty(authResponse.AccessToken));
            Assert.False(string.IsNullOrEmpty(authResponse.RefreshToken));
        }

        [Fact]
        public async Task Login_ShouldReturn401_WhenCredentialsAreInvalid()
        {
            // Arrange
            var loginRequest = new LoginRequest
            {
                IdentityType = IdentityType.Email,
                Identifier = "invaliduser@example.com",
                Password = "WrongPassword123!"
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task Login_ShouldReturn400_WhenRequestIsInvalid()
        {
            // Arrange
            var loginRequest = new LoginRequest
            {
                IdentityType = IdentityType.Email,
                Identifier = "", // Invalid email
                Password = ""
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        // Добавляем новые тесты для входа через разные каналы идентификации
        [Fact]
        public async Task Login_ShouldReturn200_WhenUsingPhoneNumber()
        {
            // Arrange
            var loginRequest = new LoginRequest
            {
                IdentityType = IdentityType.Phone,
                Identifier = "+12345678901",
                Password = "ValidPassword123!"
            };

            // Добавляем пользователя в базу данных
            using (var scope = factory.Services.CreateScope())
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

                var user = new ApplicationUser
                {
                    UserName = "phone_user",
                    Email = "phone_user@example.com",
                    PhoneNumber = loginRequest.Identifier
                };
                await userManager.CreateAsync(user, loginRequest.Password);
            }

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
            authResponse.Should().NotBeNull();
            authResponse.AccessToken.Should().NotBeNullOrEmpty();
            authResponse.RefreshToken.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task Login_ShouldReturn200_WhenUsingTelegramId()
        {
            // Arrange
            var loginRequest = new LoginRequest
            {
                IdentityType = IdentityType.Telegram,
                Identifier = "123",
                Password = null // Пароль не требуется для Telegram
            };

            // Регистрируем пользователя через Telegram
            var registerRequest = new RegisterRequest
            {
                IdentityType = IdentityType.Telegram,
                Identifier = loginRequest.Identifier,
            };
            await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
            authResponse.Should().NotBeNull();
            authResponse.AccessToken.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task Login_ShouldReturn200_WhenUsingWhatsAppNumber()
        {
            // Arrange
            var loginRequest = new LoginRequest
            {
                IdentityType = IdentityType.WhatsApp,
                Identifier = "+12345678901",
                Password = null // Пароль не требуется для WhatsApp
            };

            // Регистрируем пользователя через WhatsApp
            var registerRequest = new RegisterRequest
            {
                IdentityType = IdentityType.WhatsApp,
                Identifier = loginRequest.Identifier,
            };
            await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
            authResponse.Should().NotBeNull();
            authResponse.AccessToken.Should().NotBeNullOrEmpty();
        }
    }
}
