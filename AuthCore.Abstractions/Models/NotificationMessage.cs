namespace AuthCore.Abstractions.Models
{
    public class NotificationMessage
    {
        public required string Recipient { get; set; } // email, phone и т.п.
        public required string Subject { get; set; }
        public required string Body { get; set; }
        public NotificationType Type { get; set; } = NotificationType.Email;
    }

    public enum NotificationType
    {
        Email,
        Sms,
        Telegram,
        WhatsApp
    }
}
