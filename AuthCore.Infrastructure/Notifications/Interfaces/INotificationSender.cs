using AuthCore.Infrastructure.Notifications.Models;

namespace AuthCore.Infrastructure.Notifications.Interfaces
{
    public interface INotificationSender
    {
        Task SendAsync(NotificationMessage message, CancellationToken cancellationToken = default);
    }
}
