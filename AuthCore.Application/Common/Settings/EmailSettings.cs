using System.ComponentModel.DataAnnotations;

namespace AuthCore.Application.Common.Settings
{
    public class EmailSettings
    {
        [Required]
        public required string Host { get; set; }

        [Range(1, 65535)]
        public required int Port { get; set; }

        public required string Username { get; set; }
        public required string Password { get; set; }

        [Required]
        public required string From { get; set; }

        public bool UseSsl { get; set; } = true;
    }
}
