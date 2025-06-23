namespace AuthCore.Persistence.Entities
{
    using Microsoft.AspNetCore.Identity;
    using System.ComponentModel.DataAnnotations;

    public class ApplicationUser : IdentityUser
    {
        /// <summary>
        /// Идентификатор пользователя Telegram (числовой)
        /// </summary>
        public long? TelegramId { get; set; }

        /// <summary>
        /// Идентификатор пользователя WhatsApp (обычно номер телефона)
        /// </summary>
        [StringLength(25)]
        public string? WhatsAppId { get; set; }

        public ICollection<RefreshToken> RefreshTokens { get; set; } = [];
    }
}
