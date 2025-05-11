namespace AuthCore.Persistence.Entities
{
    public class RefreshToken
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Token { get; set; } = string.Empty;
        public bool Revoked { get; set; }
        public DateTime Created { get; set; } = DateTime.UtcNow;
        public DateTime Expires { get; set; }
        public string? ReplacedByToken { get; set; }

        public string UserId { get; set; } = null!;
        public ApplicationUser User { get; set; } = null!;
    }
}
