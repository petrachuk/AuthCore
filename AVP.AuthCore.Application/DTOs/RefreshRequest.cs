namespace AVP.AuthCore.Application.DTOs
{
    public record RefreshRequest
     {
        public string AccessToken { get; init; } = string.Empty;
        public string RefreshToken { get; init; } = string.Empty;
    };
}
