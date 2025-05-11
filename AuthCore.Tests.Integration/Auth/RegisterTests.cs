using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using AuthCore.API;
using AuthCore.Application.DTOs;
using AuthCore.Persistence.Entities;
using AuthCore.Tests.Integration.Fixtures;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AuthCore.Tests.Integration.Auth
{
    public class RegisterTests(CustomWebApplicationFactory<Program> factory)
        : IClassFixture<CustomWebApplicationFactory<Program>>
    {
        private readonly HttpClient _client = factory.CreateClient();

        [Fact]
        public async Task Register_ShouldReturn201AndAuthResponse_WhenRequestIsValid()
        {
            // Arrange
            var registerRequest = new RegisterRequest
            {
                Email = "newuser@example.com",
                Password = "StrongPassword123!"
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.Created);
            var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
            authResponse.Should().NotBeNull();
            authResponse.AccessToken.Should().NotBeNullOrEmpty();
            authResponse.RefreshToken.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task Register_ShouldReturn400_WhenRequestIsInvalid()
        {
            // Arrange
            var registerRequest = new RegisterRequest
            {
                Email = "", // Invalid email
                Password = "" // Invalid password
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task Register_ShouldReturn409_WhenEmailAlreadyExists()
        {
            // Arrange
            var registerRequest = new RegisterRequest
            {
                Email = "existinguser@example.com",
                Password = "StrongPassword123!"
            };

            // Добавляем пользователя в базу данных
            using (var scope = factory.Services.CreateScope())
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

                var user = new ApplicationUser { UserName = registerRequest.Email, Email = registerRequest.Email };
                await userManager.CreateAsync(user, registerRequest.Password);
            }

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }
    }
}
