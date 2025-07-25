﻿using System.Net;
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
                IdentityType = IdentityType.Email,
                Identifier = "newuser@example.com",
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
                IdentityType = IdentityType.Email,
                Identifier = "", // Invalid email
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
                IdentityType = IdentityType.Email,
                Identifier = "existinguser@example.com",
                Password = "StrongPassword123!"
            };

            // Добавляем пользователя в базу данных
            using (var scope = factory.Services.CreateScope())
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

                var user = new ApplicationUser { UserName = registerRequest.Identifier, Email = registerRequest.Identifier };
                await userManager.CreateAsync(user, registerRequest.Password);
            }

            // Act
            var response = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }

        // Добавляем новые тесты для регистрации через разные каналы идентификации
        [Fact]
        public async Task Register_ShouldReturn201_WhenRegisteringWithPhone()
        {
            // Arrange
            var registerRequest = new RegisterRequest
            {
                IdentityType = IdentityType.Phone,
                Identifier = "+12345678901",
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
        public async Task Register_ShouldReturn201_WhenRegisteringWithTelegram()
        {
            // Arrange
            var registerRequest = new RegisterRequest
            {
                IdentityType = IdentityType.Telegram,
                Identifier = "123",
                Password = null // Пароль необязателен
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
        public async Task Register_ShouldReturn201_WhenRegisteringWithWhatsApp()
        {
            // Arrange
            var registerRequest = new RegisterRequest
            {
                IdentityType = IdentityType.WhatsApp,
                Identifier = "+12345678901",
                Password = null // Пароль необязателен
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
    }
}
