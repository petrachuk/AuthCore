using System.Globalization;
using FluentValidation.TestHelper;
using AuthCore.Application.Validation;
using AuthCore.Application.DTOs;

namespace AuthCore.Tests.Unit.Application.Validation
{
    public class RegisterRequestValidatorTests
    {
        private readonly RegisterRequestValidator _validator;

        public RegisterRequestValidatorTests()
        {
            _validator = new RegisterRequestValidator();
            CultureInfo.DefaultThreadCurrentCulture = new CultureInfo("en-US");
            CultureInfo.DefaultThreadCurrentUICulture = new CultureInfo("en-US");
        }

        [Fact]
        public void Should_Have_Error_When_Email_Is_Empty()
        {
            // Arrange
            var model = new RegisterRequest { IdentityType = IdentityType.Email, Identifier = string.Empty, Password = "ValidPassword123" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldHaveValidationErrorFor(x => x.Identifier)
                .WithErrorMessage("Identifier cannot be empty");
        }

        [Fact]
        public void Should_Have_Error_When_Email_Is_Invalid()
        {
            // Arrange
            var model = new RegisterRequest { IdentityType = IdentityType.Email, Identifier = "invalid-email", Password = "ValidPassword123" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldHaveValidationErrorFor(x => x.Identifier)
                .WithErrorMessage("Invalid email format");
        }

        [Fact]
        public void Should_Have_Error_When_Password_Is_Empty()
        {
            // Arrange
            var model = new RegisterRequest { IdentityType = IdentityType.Email, Identifier = "test@example.com", Password = string.Empty };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldHaveValidationErrorFor(x => x.Password)
                .WithErrorMessage("Password is required for email registration");
        }

        [Fact]
        public void Should_Have_Error_When_Password_Is_Too_Short()
        {
            // Arrange
            var model = new RegisterRequest { IdentityType = IdentityType.Email, Identifier = "test@example.com", Password = "123" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldHaveValidationErrorFor(x => x.Password)
                .WithErrorMessage("Password must be at least 10 characters long");
        }

        [Fact]
        public void Should_Not_Have_Error_When_Model_Is_Valid()
        {
            // Arrange
            var model = new RegisterRequest { IdentityType = IdentityType.Email, Identifier = "test@example.com", Password = "ValidPassword123" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldNotHaveValidationErrorFor(x => x.Identifier);
            result.ShouldNotHaveValidationErrorFor(x => x.Password);
        }
    }
}
