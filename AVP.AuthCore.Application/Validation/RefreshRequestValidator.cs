using FluentValidation;
using AVP.AuthCore.Application.DTOs;

namespace AVP.AuthCore.Application.Validation
{
    public class RefreshRequestValidator : AbstractValidator<RefreshRequest>
    {
        public RefreshRequestValidator()
        {
            RuleFor(x => x.AccessToken)
                .NotEmpty();

            RuleFor(x => x.RefreshToken)
                .NotEmpty();
        }
    }
}
