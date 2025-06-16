using System.Net;
using System.Net.Mail;
using AuthCore.Abstractions.Interfaces;
using AuthCore.Abstractions.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using AuthCore.Abstractions.Settings;

namespace AuthCore.Infrastructure.Notifications.Senders
{
    public class EmailNotificationSender (IOptionsMonitor<EmailSettings> emailSettingsMonitor, ILogger<EmailNotificationSender> logger) : INotificationSender
    {
        public async Task SendAsync(NotificationMessage message, CancellationToken cancellationToken = default)
        {
            var settings = emailSettingsMonitor.CurrentValue;

            using var smtp = new SmtpClient(settings.Host, settings.Port);
            smtp.Credentials = new NetworkCredential(settings.Username, settings.Password);
            smtp.EnableSsl = settings.UseSsl;

            var mail = new MailMessage(settings.From, message.Recipient, message.Subject, message.Body)
            {
                IsBodyHtml = true
            };

            try
            {
                await smtp.SendMailAsync(mail, cancellationToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to send email notification to {To}", message.Recipient);
                throw new InvalidOperationException("Failed to send email notification", ex);
            }
        }
    }
}
