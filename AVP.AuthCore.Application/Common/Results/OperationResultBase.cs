using AVP.AuthCore.Application.Common.Errors;

namespace AVP.AuthCore.Application.Common.Results
{
    public abstract class OperationResultBase
    {
        public bool IsSuccess { get; protected set; }
        // Главная ошибка (например, "Validation.Failed")
        public ErrorCode? Error { get; protected set; }
        // Подробные ошибки (например, ["Password too short", "Email already taken"])
        public IEnumerable<ErrorCode>? Details { get; protected set; } = [];
    }
}
