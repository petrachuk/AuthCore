using FluentValidation;
using AuthCore.Application.DTOs;

namespace AuthCore.Application.Validation
{
    public class RefreshRequestValidator : AbstractValidator<RefreshRequest>
    {
        public RefreshRequestValidator()
        {
            RuleFor(x => x.AccessToken)
                .NotEmpty()
                .Must(BeAValidJwt).WithMessage("Access token must be a valid JWT.");

            RuleFor(x => x.RefreshToken)
                .NotEmpty()
                .Must(BeBase64String).WithMessage("Refresh token must be a valid Base64 string.");
        }

        private static bool BeAValidJwt(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return false;
            var parts = token.Split('.');
            return parts.Length == 3;
        }

        private bool BeBase64String(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return false;

            var buffer = new Span<byte>(new byte[token.Length]);
            return Convert.TryFromBase64String(token, buffer, out _);
        }
    }
}
