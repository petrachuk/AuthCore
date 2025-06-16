using AuthCore.Abstractions.Interfaces;
using AuthCore.Abstractions.Models;
using AuthCore.Application.Common.Errors;
using AuthCore.Application.DTOs;
using AuthCore.Application.Services;
using AuthCore.Persistence.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace AuthCore.Tests.Unit.Application.Services
{
    public class AccountServiceTests
    {
        private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
        private readonly Mock<INotificationSender> _notificationSenderMock;
        private readonly AccountService _accountService;

        public AccountServiceTests()
        {
            _userManagerMock = MockUserManager();
            _notificationSenderMock = new Mock<INotificationSender>();
            var loggerMock = new Mock<ILogger<AccountService>>();

            _accountService = new AccountService(
                _userManagerMock.Object,
                _notificationSenderMock.Object,
                loggerMock.Object
            );
        }

        #region SendConfirmationEmailAsync Tests

        [Fact]
        public async Task SendConfirmationEmailAsync_UserNotFound_ReturnsFail()
        {
            // Arrange
            var request = new VerificationRequest("notfound@example.com", string.Empty);
            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync((ApplicationUser?)null);

            // Act
            var result = await _accountService.VerifyIdentityAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.UserNotFound, result.Error);
        }

        [Fact]
        public async Task SendConfirmationEmailAsync_EmailAlreadyConfirmed_ReturnsOk()
        {
            // Arrange
            var request = new SendConfirmationRequest("confirmed@example.com");
            var user = new ApplicationUser { Email = request.Email };

            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync(user);

            _userManagerMock.Setup(x => x.IsEmailConfirmedAsync(user))
                .ReturnsAsync(true);

            // Act
            var result = await _accountService.SendConfirmationCodeAsync(request);

            // Assert
            Assert.True(result.IsSuccess);

            // Проверяем, что уведомление не отправлялось
            _notificationSenderMock.Verify(x =>
                    x.SendAsync(It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        [Fact]
        public async Task SendConfirmationEmailAsync_Success_ReturnsOk()
        {
            // Arrange
            var request = new SendConfirmationRequest("test@example.com");
            var user = new ApplicationUser { Email = request.Email };
            var token = "confirmation-token-123";

            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync(user);

            _userManagerMock.Setup(x => x.IsEmailConfirmedAsync(user))
                .ReturnsAsync(false);

            _userManagerMock.Setup(x => x.GenerateEmailConfirmationTokenAsync(user))
                .ReturnsAsync(token);

            // Act
            var result = await _accountService.SendConfirmationCodeAsync(request);

            // Assert
            Assert.True(result.IsSuccess);

            // Проверяем, что уведомление отправлено с правильным токеном
            _notificationSenderMock.Verify(x =>
                    x.SendAsync(It.Is<NotificationMessage>(m =>
                            m.Recipient == user.Email &&
                            m.Subject == "Confirm your email address" &&
                            m.Body.Contains(token)),
                        It.IsAny<CancellationToken>()),
                Times.Once);
        }

        #endregion

        #region ConfirmEmailAsync Tests

        [Fact]
        public async Task ConfirmEmailAsync_UserNotFound_ReturnsFail()
        {
            // Arrange
            var request = new VerificationRequest("notfound@example.com", "code");
            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync((ApplicationUser?)null);

            // Act
            var result = await _accountService.VerifyIdentityAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.UserNotFound, result.Error);
        }

        [Fact]
        public async Task ConfirmEmailAsync_EmailAlreadyConfirmed_ReturnsFail()
        {
            // Arrange
            var request = new VerificationRequest ("confirmed@example.com", "code");
            var user = new ApplicationUser { Email = request.Email };

            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync(user);

            _userManagerMock.Setup(x => x.IsEmailConfirmedAsync(user))
                .ReturnsAsync(true);

            // Act
            var result = await _accountService.VerifyIdentityAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.EmailAlreadyConfirmed, result.Error);
        }

        [Fact]
        public async Task ConfirmEmailAsync_InvalidToken_ReturnsFail()
        {
            // Arrange
            var request = new VerificationRequest ("test@example.com", "invalid-code");
            var user = new ApplicationUser { Email = request.Email };

            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync(user);

            _userManagerMock.Setup(x => x.IsEmailConfirmedAsync(user))
                .ReturnsAsync(false);

            _userManagerMock.Setup(x => x.ConfirmEmailAsync(user, request.ConfirmationCode))
                .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "InvalidToken", Description = "Invalid token" }));

            // Act
            var result = await _accountService.VerifyIdentityAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.InvalidEmailConfirmationToken, result.Error);
        }

        [Fact]
        public async Task ConfirmEmailAsync_Success_ReturnsOk()
        {
            // Arrange
            var request = new VerificationRequest ("test@example.com", "valid-code");
            var user = new ApplicationUser { Email = request.Email };

            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync(user);

            _userManagerMock.Setup(x => x.IsEmailConfirmedAsync(user))
                .ReturnsAsync(false);

            _userManagerMock.Setup(x => x.ConfirmEmailAsync(user, request.ConfirmationCode))
                .ReturnsAsync(IdentityResult.Success);

            // Act
            var result = await _accountService.VerifyIdentityAsync(request);

            // Assert
            Assert.True(result.IsSuccess);
        }

        #endregion

        #region SendPasswordResetEmailAsync Tests

        [Fact]
        public async Task SendPasswordResetEmailAsync_UserNotFound_ReturnsOk()
        {
            // Arrange
            var request = new PasswordResetRequest ("notfound@example.com");
            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync((ApplicationUser?)null);

            // Act
            var result = await _accountService.SendPasswordResetCodeAsync(request);

            // Assert
            // Для безопасности всегда возвращаем успех, даже если пользователь не найден
            Assert.True(result.IsSuccess);

            // Проверяем, что уведомление не отправлялось
            _notificationSenderMock.Verify(x =>
                x.SendAsync(It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        [Fact]
        public async Task SendPasswordResetEmailAsync_EmailNotConfirmed_ReturnsOk()
        {
            // Arrange
            var request = new PasswordResetRequest ("unconfirmed@example.com");
            var user = new ApplicationUser { Email = request.Email };

            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync(user);

            _userManagerMock.Setup(x => x.IsEmailConfirmedAsync(user))
                .ReturnsAsync(false);

            // Act
            var result = await _accountService.SendPasswordResetCodeAsync(request);

            // Assert
            // Для безопасности всегда возвращаем успех, даже если email не подтверждён
            Assert.True(result.IsSuccess);

            // Проверяем, что уведомление не отправлялось
            _notificationSenderMock.Verify(x =>
                x.SendAsync(It.IsAny<NotificationMessage>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        [Fact]
        public async Task SendPasswordResetEmailAsync_Success_ReturnsOk()
        {
            // Arrange
            var request = new PasswordResetRequest ("confirmed@example.com");
            var user = new ApplicationUser { Email = request.Email };
            var token = "reset-token-123";

            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync(user);

            _userManagerMock.Setup(x => x.IsEmailConfirmedAsync(user))
                .ReturnsAsync(true);

            _userManagerMock.Setup(x => x.GeneratePasswordResetTokenAsync(user))
                .ReturnsAsync(token);

            // Act
            var result = await _accountService.SendPasswordResetCodeAsync(request);

            // Assert
            Assert.True(result.IsSuccess);

            // Проверяем, что уведомление отправлено с правильным токеном
            _notificationSenderMock.Verify(x =>
                x.SendAsync(It.Is<NotificationMessage>(m =>
                    m.Recipient == user.Email &&
                    m.Subject == "Reset your password" &&
                    m.Body.Contains(token)),
                It.IsAny<CancellationToken>()),
                Times.Once);
        }

        #endregion

        #region ResetPasswordAsync Tests

        [Fact]
        public async Task ResetPasswordAsync_UserNotFound_ReturnsFail()
        {
            // Arrange
            var request = new ResetPasswordRequest("notfound@example.com", "code", "NewPass123!");
            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync((ApplicationUser?)null);

            // Act
            var result = await _accountService.ResetPasswordAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.UserNotFound, result.Error);
        }

        [Fact]
        public async Task ResetPasswordAsync_EmailNotConfirmed_ReturnsFail()
        {
            // Arrange
            var request = new ResetPasswordRequest ("unconfirmed@example.com", "code", "NewPass123!");
            var user = new ApplicationUser { Email = request.Email };

            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync(user);

            _userManagerMock.Setup(x => x.IsEmailConfirmedAsync(user))
                .ReturnsAsync(false);

            // Act
            var result = await _accountService.ResetPasswordAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.EmailNotConfirmed, result.Error);
        }

        [Fact]
        public async Task ResetPasswordAsync_InvalidToken_ReturnsFail()
        {
            // Arrange
            var request = new ResetPasswordRequest("test@example.com", "invalid-code", "NewPass123!");
            var user = new ApplicationUser { Email = request.Email };

            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync(user);

            _userManagerMock.Setup(x => x.IsEmailConfirmedAsync(user))
                .ReturnsAsync(true);

            _userManagerMock.Setup(x => x.ResetPasswordAsync(user, request.ResetCode, request.NewPassword))
                .ReturnsAsync(IdentityResult.Failed(new IdentityError { Code = "InvalidToken", Description = "Invalid token" }));

            // Act
            var result = await _accountService.ResetPasswordAsync(request);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(ErrorCode.InvalidPasswordResetToken, result.Error);
        }

        [Fact]
        public async Task ResetPasswordAsync_Success_ReturnsOk()
        {
            // Arrange
            var request = new ResetPasswordRequest("test@example.com", "valid-code", "NewPass123!");
            var user = new ApplicationUser { Email = request.Email };

            _userManagerMock.Setup(x => x.FindByEmailAsync(request.Email))
                .ReturnsAsync(user);

            _userManagerMock.Setup(x => x.IsEmailConfirmedAsync(user))
                .ReturnsAsync(true);

            _userManagerMock.Setup(x => x.ResetPasswordAsync(user, request.ResetCode, request.NewPassword))
                .ReturnsAsync(IdentityResult.Success);

            // Act
            var result = await _accountService.ResetPasswordAsync(request);

            // Assert
            Assert.True(result.IsSuccess);
        }

        #endregion

        #region Helpers

        private static Mock<UserManager<ApplicationUser>> MockUserManager()
        {
            var store = new Mock<IUserStore<ApplicationUser>>();
            var options = new Mock<IOptions<IdentityOptions>>();
            var passwordHasher = new Mock<IPasswordHasher<ApplicationUser>>();
            var userValidators = new List<IUserValidator<ApplicationUser>>();
            var passwordValidators = new List<IPasswordValidator<ApplicationUser>>();
            var keyNormalizer = new Mock<ILookupNormalizer>();
            var errors = new Mock<IdentityErrorDescriber>();
            var services = new Mock<IServiceProvider>();
            var logger = new Mock<ILogger<UserManager<ApplicationUser>>>();

            return new Mock<UserManager<ApplicationUser>>(
                store.Object, options.Object, passwordHasher.Object,
                userValidators, passwordValidators, keyNormalizer.Object,
                errors.Object, services.Object, logger.Object);
        }

        #endregion
    }
}