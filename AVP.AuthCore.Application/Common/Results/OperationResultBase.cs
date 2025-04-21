namespace AVP.AuthCore.Application.Common.Results
{
    public abstract class OperationResultBase
    {
        public bool IsSuccess { get; protected set; }
        public string[] Errors { get; protected set; } = [];
    }
}
