namespace AVP.AuthCore.Application.DTOs
{
    public record AuthResponse(
        bool IsSuccessful,
        string AccessToken,
        string RefreshToken,
        DateTime ExpiresAt,
        List<string> Errors
    )
    {
        public AuthResponse() : this(false, string.Empty, string.Empty, DateTime.MinValue, [])
        {
        }
    }
}
