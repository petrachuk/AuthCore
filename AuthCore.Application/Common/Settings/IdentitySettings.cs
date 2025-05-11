using System.ComponentModel.DataAnnotations;

namespace AuthCore.Application.Common.Settings
{
    public class IdentitySettings
    {
        [Required]
        public string DefaultUserRole { get; set; } = "User";
    }
}
