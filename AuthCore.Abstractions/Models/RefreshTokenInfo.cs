namespace AuthCore.Abstractions.Models
{
    public class RefreshTokenInfo
    {
        public string Token { get; set; } = null!;
        public string UserId { get; set; } = null!;
        public DateTime Expires { get; set; }
    }
}
