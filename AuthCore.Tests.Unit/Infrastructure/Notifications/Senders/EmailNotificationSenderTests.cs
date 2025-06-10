using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using AuthCore.Application.Common.Settings;
using AuthCore.Infrastructure.Notifications.Models;
using AuthCore.Infrastructure.Notifications.Senders;

namespace AuthCore.Tests.Unit.Infrastructure.Notifications.Senders
{
    public class EmailNotificationSenderTests
    {
        private readonly Mock<IOptionsMonitor<EmailSettings>> _settingsMock;
        private readonly Mock<ILogger<EmailNotificationSender>> _loggerMock;

        public EmailNotificationSenderTests()
        {
            _settingsMock = new Mock<IOptionsMonitor<EmailSettings>>();
            _loggerMock = new Mock<ILogger<EmailNotificationSender>>();
        }

        [Theory]
        [InlineData("smtp.test.com", 587, "from@test.com")]
        [InlineData("smtp.example.com", 2525, "from@example.com")]
        public async Task SendAsync_WithVariousValidSettings_ThrowsOnConnectionFailure(string host, int port, string from)
        {
            // Arrange
            var settings = new EmailSettings
            {
                Host = host,
                Port = port,
                Username = "user",
                Password = "pass",
                From = from,
                UseSsl = true
            };
            _settingsMock.Setup(x => x.CurrentValue).Returns(settings);

            var sender = new EmailNotificationSender(_settingsMock.Object, _loggerMock.Object);

            var message = new NotificationMessage
            {
                Recipient = "to@example.com",
                Subject = "Subject",
                Body = "<b>Body</b>"
            };

            // Act & Assert
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
                sender.SendAsync(message, CancellationToken.None));
        }

        [Fact]
        public async Task SendAsync_SmtpThrows_LogsAndThrowsInvalidOperationException()
        {
            // Arrange
            var settings = new EmailSettings
            {
                Host = "invalid",
                Port = 25,
                Username = "user",
                Password = "pass",
                From = "from@test.com",
                UseSsl = false
            };
            _settingsMock.Setup(x => x.CurrentValue).Returns(settings);

            var sender = new EmailNotificationSender(_settingsMock.Object, _loggerMock.Object);

            var message = new NotificationMessage
            {
                Recipient = "to@test.com",
                Subject = "Test",
                Body = "Body"
            };

            // Act & Assert
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                sender.SendAsync(message, CancellationToken.None));

            Assert.Contains("Failed to send email notification", ex.Message);
            _loggerMock.Verify(
                l => l.Log(
                    LogLevel.Error,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Failed to send email notification")),
                    It.IsAny<Exception>(),
                    It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
                Times.Once);
        }
    }
}
