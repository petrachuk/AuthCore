using System.ComponentModel.DataAnnotations;

namespace AVP.AuthCore.Application.Common.Settings
{
    public class IdentitySettings
    {
        [Required]
        public string DefaultUserRole { get; set; } = "User";
    }
}
