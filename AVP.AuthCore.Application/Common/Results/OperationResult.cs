namespace AVP.AuthCore.Application.Common.Results
{
    public class OperationResult : OperationResultBase
    {
        public static OperationResult Ok() => new()
        {
            IsSuccess = true
        };

        public static OperationResult Fail(params string[] errors) => new()
        {
            IsSuccess = false,
            Errors = errors
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

        public static OperationResult<T> Fail(params string[] errors) => new()
        {
            IsSuccess = false,
            Errors = errors
        };
    }
}
