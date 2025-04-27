using System.ComponentModel.DataAnnotations;

namespace AVP.AuthCore.Application.Common.Settings
{
    public class JwtSettings
    {
        [Required]
        public string Key { get; set; } = string.Empty;

        [Required]
        public string Issuer { get; set; } = string.Empty;

        [Required]
        public string Audience { get; set; } = string.Empty;

        [Range(1, int.MaxValue)]
        public int AccessTokenLifetimeMinutes { get; set; } = 15;

        [Range(1, int.MaxValue)]
        public int RefreshTokenLifetimeDays { get; set; } = 7;
    }
}
