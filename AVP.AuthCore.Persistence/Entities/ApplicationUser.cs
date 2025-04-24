namespace AVP.AuthCore.Persistence.Entities
{
    using Microsoft.AspNetCore.Identity;

    public class ApplicationUser : IdentityUser
    {
        public ICollection<RefreshToken> RefreshTokens { get; set; } = [];
    }
}
