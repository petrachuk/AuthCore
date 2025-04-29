using AVP.AuthCore.Application.Common.Errors;

namespace AVP.AuthCore.Application.Common.Results
{
    public class OperationResult : OperationResultBase
    {
        public static OperationResult Ok(bool isCreated = false) => new()
        {
            IsSuccess = true,
            IsCreated = isCreated
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

        // Ошибка с сообщениями
        public static OperationResult Fail(ErrorCode errorCode, IEnumerable<ErrorCode>? details, IEnumerable<string>? rawMessages) => new()
        {
            IsSuccess = false,
            Error = errorCode,
            Details = details,
            RawMessages = rawMessages
        };
    }

    public class OperationResult<T> : OperationResultBase
    {
        public T? Data { get; private set; }

        // успех
        public static OperationResult<T> Ok(T data, bool isCreated = false) => new()
        {
            IsSuccess = true,
            Data = data,
            IsCreated = isCreated
        };

        public static OperationResult<T> Fail(ErrorCode errorCode) => new()
        {
            IsSuccess = false,
            Error = errorCode
        };

        // ошибка (только код)
        public static OperationResult<T> Fail(ErrorCode errorCode, IEnumerable<ErrorCode> details) => new()
        {
            IsSuccess = false,
            Error = errorCode,
            Details = details
        };

        // ошибка с сообщениями
        public static OperationResult<T> Fail(ErrorCode errorCode, IEnumerable<ErrorCode> details, IEnumerable<string> rawMessages) => new()
        {
            IsSuccess = false,
            Error = errorCode,
            Details = details,
            RawMessages = rawMessages
        };
    }
}
