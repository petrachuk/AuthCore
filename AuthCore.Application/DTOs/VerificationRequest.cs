namespace AuthCore.Application.DTOs
{
    public record VerificationRequest(string Email, string ConfirmationCode);
}
