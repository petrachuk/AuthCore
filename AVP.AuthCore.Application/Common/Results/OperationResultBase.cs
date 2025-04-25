using AVP.AuthCore.Application.Common.Errors;

namespace AVP.AuthCore.Application.Common.Results
{
    public abstract class OperationResultBase
    {
        public bool IsSuccess { get; protected set; }
        // основной код ошибки
        public ErrorCode? Error { get; protected set; }
        // дополнительные коды ошибок
        public IEnumerable<ErrorCode>? Details { get; protected set; } = [];
        // сырые ошибки
        public IEnumerable<string>? RawMessages { get; init; }
    }
}
