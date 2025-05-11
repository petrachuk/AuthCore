using AuthCore.Application.Common.Errors;
using Microsoft.AspNetCore.Identity;

namespace AuthCore.Application.Common.Results
{
    public abstract class OperationResultBase
    {
        public bool IsSuccess { get; protected set; }
        public bool IsCreated { get; init; } = false;
        // основной код ошибки
        public ErrorCode? Error { get; protected set; }
        // дополнительные коды ошибок
        public IEnumerable<IdentityError>? Details { get; protected set; } = [];
    }
}
