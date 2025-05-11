namespace AuthCore.Application.DTOs
{
    /// <summary>
    /// Response containing authorization tokens
    /// </summary>
    /// <param name="AccessToken">JWT access token</param>
    /// <param name="RefreshToken">Refresh token to extend the session</param>
    /// <param name="ExpiresAt">The expiration time of the access token</param>
    public record AuthResponse(string AccessToken, string RefreshToken, DateTime ExpiresAt);
}
