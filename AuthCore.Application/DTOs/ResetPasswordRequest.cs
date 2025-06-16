namespace AuthCore.Application.DTOs
{
    public record ResetPasswordRequest(string Email, string ResetCode, string NewPassword);
}
