namespace AuthCore.Application.DTOs
{
    /// <summary>
    /// Request for token refresh
    /// </summary>
    public record RefreshRequest
     {
         /// <summary>
         /// The current access token
         /// </summary>
         public string AccessToken { get; init; } = string.Empty;

         /// <summary>
         /// The refresh token
         /// </summary>
         public string RefreshToken { get; init; } = string.Empty;
    };
}
