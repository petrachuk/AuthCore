using System.Net;
using System.Net.Http.Json;
using AVP.AuthCore.API;
using FluentAssertions;
using AVP.AuthCore.Application.DTOs;
using AVP.AuthCore.Tests.Integration.Fixtures;

namespace AVP.AuthCore.Tests.Integration.Auth
{
    public class RefreshTests(CustomWebApplicationFactory<Program> factory)
        : IClassFixture<CustomWebApplicationFactory<Program>>
    {
        private readonly HttpClient _client = factory.CreateClient();

        [Fact]
        public async Task Refresh_ShouldReturn200AndNewTokens_WhenRegistrationIsValid()
        {
            // Arrange
            var registerRequest = new RegisterRequest
            {
                Email = "newuser@example.com",
                Password = "ValidPassword123!"
            };

            // Регистрация для получения токенов
            var registerResponse = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);
            var authResponse = await registerResponse.Content.ReadFromJsonAsync<AuthResponse>();

            var refreshRequest = new RefreshRequest
            {
                AccessToken = authResponse!.AccessToken,
                RefreshToken = authResponse.RefreshToken
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/refresh", refreshRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var newAuthResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
            newAuthResponse.Should().NotBeNull();
            newAuthResponse!.AccessToken.Should().NotBeNullOrEmpty();
            newAuthResponse.RefreshToken.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task Refresh_ShouldReturn200AndNewTokens_WhenLoginIsValid()
        {
            // Arrange
            var loginRequest = new LoginRequest
            {
                Email = "testuser@example.com",
                Password = "ValidPassword123!"
            };

            // Предварительная регистрация пользователя
            await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest
            {
                Email = loginRequest.Email,
                Password = loginRequest.Password
            });

            // Логин для получения токенов
            var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);
            var authResponse = await loginResponse.Content.ReadFromJsonAsync<AuthResponse>();

            var refreshRequest = new RefreshRequest
            {
                AccessToken = authResponse!.AccessToken,
                RefreshToken = authResponse.RefreshToken
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/refresh", refreshRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            var newAuthResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();
            newAuthResponse.Should().NotBeNull();
            newAuthResponse!.AccessToken.Should().NotBeNullOrEmpty();
            newAuthResponse.RefreshToken.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task Refresh_ShouldReturn403_WhenRefreshTokenIsInvalid()
        {
            // Arrange

            var registerRequest = new RegisterRequest
            {
                Email = "olduser@example.com",
                Password = "ValidPassword123!"
            };

            // Регистрация для получения токенов
            var registerResponse = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);
            var authResponse = await registerResponse.Content.ReadFromJsonAsync<AuthResponse>();

            // заменяем RefreshToken на недействительный
            var refreshRequest = new RefreshRequest
            {
                AccessToken = authResponse!.AccessToken,
                RefreshToken = "aW52YWxpZC1yZWZyZXNoLXRva2Vu"
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/refresh", refreshRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }

        [Fact]
        public async Task Refresh_ShouldReturn400_WhenRequestIsInvalid()
        {
            // Arrange
            var refreshRequest = new RefreshRequest
            {
                AccessToken = "", // Invalid access token
                RefreshToken = "" // Invalid refresh token
            };

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/refresh", refreshRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }
    }
}
