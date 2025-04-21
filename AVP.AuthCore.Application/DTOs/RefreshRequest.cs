namespace AVP.AuthCore.Application.DTOs
{
    public record RefreshRequest(string AccessToken, string RefreshToken);
}
