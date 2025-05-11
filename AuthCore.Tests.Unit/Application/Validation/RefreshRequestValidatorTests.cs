using System.Globalization;
using FluentValidation.TestHelper;
using AuthCore.Application.Validation;
using AuthCore.Application.DTOs;

namespace AuthCore.Tests.Unit.Application.Validation
{
    public class RefreshRequestValidatorTests
    {
        private readonly RefreshRequestValidator _validator;

        public RefreshRequestValidatorTests()
        {
            _validator = new RefreshRequestValidator();
            CultureInfo.DefaultThreadCurrentCulture = new CultureInfo("en-US");
            CultureInfo.DefaultThreadCurrentUICulture = new CultureInfo("en-US");
        }

        [Fact]
        public void Should_Have_Error_When_AccessToken_Is_Empty()
        {
            // Arrange
            var model = new RefreshRequest { AccessToken = string.Empty, RefreshToken = "ValidRefreshToken" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldHaveValidationErrorFor(x => x.AccessToken)
                .WithErrorMessage("'Access Token' must not be empty.");
        }

        [Fact]
        public void Should_Have_Error_When_RefreshToken_Is_Empty()
        {
            // Arrange
            var model = new RefreshRequest { AccessToken = "ValidAccessToken", RefreshToken = string.Empty };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldHaveValidationErrorFor(x => x.RefreshToken)
                .WithErrorMessage("'Refresh Token' must not be empty.");
        }

        [Fact]
        public void Should_Not_Have_Error_When_Model_Is_Valid()
        {
            // Arrange
            var model = new RefreshRequest
            {
                AccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2ZWE4ZjNiOC1mMzYzLTQ3NzEtODczYy0zM2JlMDJiNjE5MDQiLCJqdGkiOiI3MzlhMmRkYS1hMTBlLTQ1MzgtYTRhNC1jMjg4ZWNhZjk2M2EiLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOiJVc2VyIiwiZXhwIjoxNzQ2NzAzNzA5LCJpc3MiOiJBdXRoQ29yZVNlcnZlciIsImF1ZCI6IkF1dGhDb3JlQ2xpZW50In0.34dLUn3xvF6BlAEf0UARNCg9HqfrsclxIN9iFFHhaLE",
                RefreshToken = "kVHp02L7P5Jhj2+nbTg9yJ02JXkzj0T4dfLPdDVQRUD/2wwrRS4y67kFRSKDTWMU9EGKT+1HbwlGzo5PZZtIqQ=="
            };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldNotHaveValidationErrorFor(x => x.AccessToken);
            result.ShouldNotHaveValidationErrorFor(x => x.RefreshToken);
        }
    }
}