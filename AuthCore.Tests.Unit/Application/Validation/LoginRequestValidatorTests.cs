using AuthCore.Application.DTOs;
using AuthCore.Application.Validation;
using FluentValidation.TestHelper;
using System.Globalization;

namespace AuthCore.Tests.Unit.Application.Validation
{
    public class LoginRequestValidatorTests
    {
        public LoginRequestValidatorTests()
        {
            CultureInfo.DefaultThreadCurrentCulture = new CultureInfo("en-US");
            CultureInfo.DefaultThreadCurrentUICulture = new CultureInfo("en-US");
        }

        private readonly LoginRequestValidator _validator = new();

        [Fact]
        public void Should_Have_Error_When_Email_Is_Empty()
        {
            // Arrange
            var model = new LoginRequest { IdentityType = IdentityType.Email, Identifier = string.Empty, Password = "ValidPassword123" };

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
            var model = new LoginRequest { IdentityType = IdentityType.Email, Identifier = "invalid-email", Password = "ValidPassword123" };

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
            var model = new LoginRequest { IdentityType = IdentityType.Email, Identifier = "test@example.com", Password = string.Empty };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldHaveValidationErrorFor(x => x.Password)
                .WithErrorMessage("Password is required for email login");
        }

        [Fact]
        public void Should_Have_Error_When_Password_Is_Too_Short()
        {
            // Arrange
            var model = new LoginRequest { IdentityType = IdentityType.Email, Identifier = "test@example.com", Password = "123" };

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
            var model = new LoginRequest { IdentityType = IdentityType.Email, Identifier = "test@example.com", Password = "ValidPassword123" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldNotHaveValidationErrorFor(x => x.Identifier);
            result.ShouldNotHaveValidationErrorFor(x => x.Password);
        }

        // Новые тесты для телефона
        [Fact]
        public void Should_Have_Error_When_Phone_Format_Is_Invalid()
        {
            // Arrange
            var model = new LoginRequest { IdentityType = IdentityType.Phone, Identifier = "invalid-phone", Password = "ValidPassword123" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldHaveValidationErrorFor(x => x.Identifier)
                .WithErrorMessage("Invalid phone number format. Use international format");
        }

        [Fact]
        public void Should_Not_Have_Error_When_Phone_Format_Is_Valid()
        {
            // Arrange
            var model = new LoginRequest { IdentityType = IdentityType.Phone, Identifier = "+12345678901", Password = "ValidPassword123" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldNotHaveValidationErrorFor(x => x.Identifier);
        }

        [Fact]
        public void Should_Have_Error_When_Phone_Password_Is_Empty()
        {
            // Arrange
            var model = new LoginRequest { IdentityType = IdentityType.Phone, Identifier = "+12345678901", Password = string.Empty };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldHaveValidationErrorFor(x => x.Password)
                .WithErrorMessage("Password is required for phone login");
        }

        // Новые тесты для Telegram
        [Fact]
        public void Should_Have_Error_When_Telegram_Id_Is_Invalid()
        {
            // Arrange
            var model = new LoginRequest { IdentityType = IdentityType.Telegram, Identifier = "inv", Password = "ValidPassword123" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldHaveValidationErrorFor(x => x.Identifier)
                .WithErrorMessage("Invalid Telegram ID format");
        }

        [Fact]
        public void Should_Not_Have_Error_When_Telegram_Id_Is_Valid_Username()
        {
            // Arrange
            var model = new LoginRequest { IdentityType = IdentityType.Telegram, Identifier = "username_123" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldNotHaveValidationErrorFor(x => x.Identifier);
        }

        [Fact]
        public void Should_Not_Have_Error_When_Telegram_Id_Is_Valid_Number()
        {
            // Arrange
            var model = new LoginRequest { IdentityType = IdentityType.Telegram, Identifier = "12345678" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldNotHaveValidationErrorFor(x => x.Identifier);
        }

        [Fact]
        public void Should_Not_Require_Password_For_Telegram()
        {
            // Arrange
            var model = new LoginRequest { IdentityType = IdentityType.Telegram, Identifier = "username_123", Password = string.Empty };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldNotHaveValidationErrorFor(x => x.Password);
        }

        // Новые тесты для WhatsApp
        [Fact]
        public void Should_Have_Error_When_WhatsApp_Number_Is_Invalid()
        {
            // Arrange
            var model = new LoginRequest { IdentityType = IdentityType.WhatsApp, Identifier = "invalid-whatsapp" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldHaveValidationErrorFor(x => x.Identifier)
                .WithErrorMessage("Invalid WhatsApp number format. Use international format");
        }

        [Fact]
        public void Should_Not_Have_Error_When_WhatsApp_Number_Is_Valid()
        {
            // Arrange
            var model = new LoginRequest { IdentityType = IdentityType.WhatsApp, Identifier = "+12345678901" };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldNotHaveValidationErrorFor(x => x.Identifier);
        }

        [Fact]
        public void Should_Not_Require_Password_For_WhatsApp()
        {
            // Arrange
            var model = new LoginRequest { IdentityType = IdentityType.WhatsApp, Identifier = "+12345678901", Password = string.Empty };

            // Act
            var result = _validator.TestValidate(model);

            // Assert
            result.ShouldNotHaveValidationErrorFor(x => x.Password);
        }
    }
}