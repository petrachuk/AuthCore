using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using FluentAssertions;
using AVP.AuthCore.Tests.Integration.Fixtures;
using AVP.AuthCore.API;
using AVP.AuthCore.Application.DTOs;
using AVP.AuthCore.Persistence.Entities;

namespace AVP.AuthCore.Tests.Integration.Auth
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
                Email = "testuser@example.com",
                Password = "ValidPassword123!"
            };

            // Добавляем пользователя в базу данных
            using (var scope = factory.Services.CreateScope())
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

                var user = new ApplicationUser { UserName = loginRequest.Email, Email = loginRequest.Email };
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
                Email = "invaliduser@example.com",
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
                Email = "", // Invalid email
                Password = ""
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }
    }
}
