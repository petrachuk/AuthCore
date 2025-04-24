using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using AVP.AuthCore.Application.Common.Results;
using AVP.AuthCore.Application.Common.Errors;
using AVP.AuthCore.Application.Resources;

namespace AVP.AuthCore.API.Extensions
{
    public static class ResultExtensions
    {
        public static IActionResult ToActionResult(this OperationResult result, ILogger logger, IStringLocalizer<ErrorMessages> localizer)
        {
            if (result.IsSuccess)
            {
                logger.LogInformation("Request succeeded");
                return new NoContentResult();
            }

            logger.LogWarning("Request failed with errors: {Errors}", string.Join(" ", result.Details));
            return BuildErrorResult(result.Error, result.Details, localizer);
        }

        public static IActionResult ToActionResult<T>(this OperationResult<T> result, ILogger logger, IStringLocalizer<ErrorMessages> localizer)
        {
            if (result.IsSuccess)
            {
                logger.LogInformation("Request succeeded with data: {Data}", result.Data);
                return new OkObjectResult(result.Data);
            }

            logger.LogWarning("Request failed with errors: {Errors}", string.Join(" ", result.Details));
            return BuildErrorResult(result.Error, result.Details, localizer);
        }

        private static IActionResult BuildErrorResult(ErrorCode? error, IEnumerable<ErrorCode>? details, IStringLocalizer<ErrorMessages> localizer)
        {
            // локализация главной ошибки
            var mainMessageKey = error.HasValue ? ErrorCatalog.GetMessageKey(error.Value) : "Unknown";
            var localizedMainMessage = localizer[mainMessageKey].Value;

            // локализация деталей
            var localizedDetails = details?
                .Select(code => localizer[ErrorCatalog.GetMessageKey(code)].Value)
                .ToList() ?? [];

            var problemDetails = new ProblemDetails
            {
                Detail = localizedMainMessage,
                Extensions = { ["errors"] = localizedDetails }
            };

            return error switch
            {
                ErrorCode.InvalidAccessToken or ErrorCode.RefreshTokenExpired => SetProblemResult(problemDetails, "Unauthorized", StatusCodes.Status401Unauthorized),
                ErrorCode.UserNotFound => SetProblemResult(problemDetails, "Not Found", StatusCodes.Status404NotFound),
                _ => SetProblemResult(problemDetails, "Bad Request", StatusCodes.Status400BadRequest)
            };
        }

        private static IActionResult SetProblemResult(ProblemDetails problem, string title, int status)
        {
            problem.Title = title;
            problem.Status = status;

            return status switch
            {
                StatusCodes.Status401Unauthorized => new UnauthorizedObjectResult(problem),
                StatusCodes.Status404NotFound => new NotFoundObjectResult(problem),
                _ => new BadRequestObjectResult(problem)
            };
        }
    }
}
