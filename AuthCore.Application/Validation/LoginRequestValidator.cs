using AuthCore.Application.DTOs;
using FluentValidation;

namespace AuthCore.Application.Validation
{
    public class LoginRequestValidator : AbstractValidator<LoginRequest>
    {
        public LoginRequestValidator()
        {
            RuleFor(x => x.IdentityType)
                .IsInEnum()
                .WithMessage("Invalid identifier type");

            RuleFor(x => x.Identifier)
                .NotEmpty()
                .WithMessage("Identifier cannot be empty");

            // Conditional validation based on identifier type
            When(x => x.IdentityType == IdentityType.Email, () => {
                RuleFor(x => x.Identifier)
                    .EmailAddress()
                    .WithMessage("Invalid email format");

                RuleFor(x => x.Password)
                    .NotEmpty()
                    .WithMessage("Password is required for email login")
                    .MinimumLength(10)
                    .WithMessage("Password must be at least 10 characters long");
            });

            When(x => x.IdentityType == IdentityType.Phone, () => {
                RuleFor(x => x.Identifier)
                    .Matches(@"^\+?[1-9]\d{1,14}$")
                    .WithMessage("Invalid phone number format. Use international format");

                RuleFor(x => x.Password)
                    .NotEmpty()
                    .WithMessage("Password is required for phone login")
                    .MinimumLength(10)
                    .WithMessage("Password must be at least 10 characters long");
            });

            When(x => x.IdentityType == IdentityType.Telegram, () => {
                RuleFor(x => x.Identifier)
                    .Must(BeValidTelegramId)
                    .WithMessage("Invalid Telegram ID format");

                // Password is not required for Telegram
            });

            When(x => x.IdentityType == IdentityType.WhatsApp, () => {
                RuleFor(x => x.Identifier)
                    .Matches(@"^\+?[1-9]\d{1,14}$")
                    .WithMessage("Invalid WhatsApp number format. Use international format");

                // Password is not required for WhatsApp
            });
        }

        private bool BeValidTelegramId(string id)
        {
            return TelegramIdValidator.IsValid(id);
        }
    }
}
