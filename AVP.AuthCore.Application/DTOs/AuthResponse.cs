namespace AVP.AuthCore.Application.DTOs
{
    public record AuthResponse(string AccessToken, string RefreshToken, DateTime ExpiresAt);
}
