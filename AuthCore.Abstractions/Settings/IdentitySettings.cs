using System.ComponentModel.DataAnnotations;

namespace AuthCore.Abstractions.Settings
{
    public class IdentitySettings
    {
        [Required]
        public string DefaultUserRole { get; set; } = "User";
    }
}
