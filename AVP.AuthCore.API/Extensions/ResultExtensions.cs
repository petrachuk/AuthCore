using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using AVP.AuthCore.Application.Common.Results;
using AVP.AuthCore.Application.Common.Errors;

namespace AVP.AuthCore.API.Extensions
{
    public static class ResultExtensions
    {
        public static IActionResult ToActionResult(this OperationResult result, ILogger logger, HttpContext httpContext)
        {
            if (result.IsSuccess)
            {
                logger.LogInformation("Request succeeded");

                return result.IsCreated ? new StatusCodeResult(StatusCodes.Status201Created) : new NoContentResult();
            }

            logger.LogWarning("Request failed with errors: {Errors}", string.Join(" ", result.Details ?? []));
            return BuildErrorResult(result.Error, result.Details, httpContext);
        }

        public static IActionResult ToActionResult<T>(this OperationResult<T> result, ILogger logger, HttpContext httpContext)
        {
            if (result.IsSuccess)
            {
                logger.LogInformation("Request succeeded with data: {Data}", result.Data);

                if (result.IsCreated)
                {
                    return new ObjectResult(result.Data)
                    {
                        StatusCode = StatusCodes.Status201Created
                        // Опционально: Location = ..., если будет ссылка на созданный ресурс
                    };
                }

                return new OkObjectResult(result.Data);
            }

            logger.LogWarning("Request failed with errors: {Errors}", string.Join(" ", result.Details?.Select(e => e.Code) ?? []));
            return BuildErrorResult(result.Error, result.Details, httpContext);
        }

        private static IActionResult BuildErrorResult(ErrorCode? error, IEnumerable<IdentityError>? details, HttpContext httpContext)
        {
            //var errorMessage = error.FirstOrDefault() ?? "An error occurred";

            var problemDetails = new ProblemDetails
            {
                Type = "https://tools.ietf.org/html/rfc7231#section-6.5.1",
                // Detail = mainMessageKey,
                Instance = httpContext.Request.Path,
                Extensions = {
                    ["errors"] = details,
                    ["traceId"] = httpContext.TraceIdentifier
                }
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
