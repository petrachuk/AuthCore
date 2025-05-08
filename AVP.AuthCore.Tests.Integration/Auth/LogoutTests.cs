using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using FluentAssertions;
using AVP.AuthCore.Tests.Integration.Fixtures;
using AVP.AuthCore.API;
using AVP.AuthCore.Application.DTOs;
using AVP.AuthCore.Persistence.Entities;
using System.Net.Http.Headers;

namespace AVP.AuthCore.Tests.Integration.Auth
{
    public class LogoutTests(CustomWebApplicationFactory<Program> factory)
        : IClassFixture<CustomWebApplicationFactory<Program>>
    {
        private readonly HttpClient _client = factory.CreateClient();

        [Fact]
        public async Task Logout_ShouldReturn204_WhenRefreshTokenIsValid()
        {
            // Arrange
            var registerRequest = new RegisterRequest
            {
                Email = "logoutuser@example.com",
                Password = "SecurePassword123!"
            };

            var registerResponse = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);
            var authResponse = await registerResponse.Content.ReadFromJsonAsync<AuthResponse>();

            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authResponse!.AccessToken);

            var logoutRequest = new RefreshRequest
            {
                AccessToken = authResponse.AccessToken,
                RefreshToken = authResponse.RefreshToken
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/logout", logoutRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.NoContent);
        }

        [Fact]
        public async Task Logout_ShouldReturn403_WhenRefreshTokenIsInvalid()
        {
            // Arrange
            var registerRequest = new RegisterRequest
            {
                Email = "invalidlogout@example.com",
                Password = "StrongPass!456"
            };

            var registerResponse = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);
            var authResponse = await registerResponse.Content.ReadFromJsonAsync<AuthResponse>();

            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authResponse!.AccessToken);

            var logoutRequest = new RefreshRequest
            {
                AccessToken = authResponse.AccessToken,
                RefreshToken = "aW52YWxpZC1yZWZyZXNoLXRva2Vu"
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/logout", logoutRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }

        [Fact]
        public async Task Logout_ShouldReturn401_WhenUserIsNotAuthorized()
        {
            // Arrange
            var logoutRequest = new RefreshRequest
            {
                AccessToken = "any",
                RefreshToken = "any"
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/logout", logoutRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

    }
}
