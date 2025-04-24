using AVP.AuthCore.Application.Common.Errors;

namespace AVP.AuthCore.Application.Common.Results
{
    public class OperationResult : OperationResultBase
    {
        public static OperationResult Ok() => new()
        {
            IsSuccess = true
        };

        public static OperationResult Fail(ErrorCode errorCode) => new()
        {
            IsSuccess = false,
            Error = errorCode
        };

        public static OperationResult Fail(ErrorCode errorCode, IEnumerable<ErrorCode> details) => new()
        {
            IsSuccess = false,
            Error = errorCode,
            Details = details
        };
    }

    public class OperationResult<T> : OperationResultBase
    {
        public T? Data { get; private set; }

        public static OperationResult<T> Ok(T data) => new()
        {
            IsSuccess = true,
            Data = data
        };

        public static OperationResult<T> Fail(ErrorCode errorCode) => new()
        {
            IsSuccess = false,
            Error = errorCode
        };

        public static OperationResult<T> Fail(ErrorCode errorCode, IEnumerable<ErrorCode> details) => new()
        {
            IsSuccess = false,
            Error = errorCode,
            Details = details
        };
    }
}
