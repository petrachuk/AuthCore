using AuthCore.Abstractions.Models;

namespace AuthCore.Abstractions.Interfaces
{
    public interface INotificationSender
    {
        Task SendAsync(NotificationMessage message, CancellationToken cancellationToken = default);
    }
}
