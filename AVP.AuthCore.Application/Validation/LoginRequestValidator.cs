using FluentValidation;
using AVP.AuthCore.Application.DTOs;

namespace AVP.AuthCore.Application.Validation
{
    public class LoginRequestValidator : AbstractValidator<LoginRequest>

    {
        public LoginRequestValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty()
                .EmailAddress();

            RuleFor(x => x.Password)
                .NotEmpty()
                .MinimumLength(6);
        }
    }
}
