using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using AuthCore.Infrastructure.Notifications.Interfaces;
using AuthCore.Infrastructure.Notifications.Senders;

namespace AuthCore.Infrastructure.Notifications.Extensions
{
    public static class NotificationExtensions
    {
        public static IServiceCollection AddNotificationSenders(this IServiceCollection services, IConfiguration configuration)
        {
            // пока добавим только Email, потом — SMS, Telegram, и т.п.
            services.AddTransient<INotificationSender, EmailNotificationSender>();

            return services;
        }
    }
}
