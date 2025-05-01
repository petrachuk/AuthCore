using System.Globalization;
using FluentValidation.TestHelper;
using AVP.AuthCore.Application.Validation;
using AVP.AuthCore.Application.DTOs;

namespace AVP.AuthCore.Tests.Unit.Application.Validation
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
            var model = new RefreshRequest { AccessToken = "ValidAccessToken", RefreshToken = "ValidRefreshToken" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldNotHaveValidationErrorFor(x => x.AccessToken);
            result.ShouldNotHaveValidationErrorFor(x => x.RefreshToken);
        }
    }
}