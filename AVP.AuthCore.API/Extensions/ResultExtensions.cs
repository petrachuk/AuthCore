using Microsoft.AspNetCore.Mvc;
using AVP.AuthCore.Application.Common.Results;

namespace AVP.AuthCore.API.Extensions
{
    public static class ResultExtensions
    {
        public static IActionResult ToActionResult(this OperationResult result, ILogger logger)
        {
            if (result.IsSuccess)
            {
                logger.LogInformation("Request succeeded.");
                return new NoContentResult();
            }

            var errorMessage = result.Errors.FirstOrDefault() ?? "An error occurred";

            logger.LogWarning("Request failed with errors: {Errors}", string.Join(" ", result.Errors));
            return errorMessage switch
            {
                "Invalid access token" => new UnauthorizedObjectResult(new ProblemDetails
                {
                    Title = "Unauthorized",
                    Detail = string.Join(" ", result.Errors),
                    Status = StatusCodes.Status401Unauthorized
                }),
                "User not found" => new NotFoundObjectResult(new ProblemDetails
                {
                    Title = "Not Found",
                    Detail = string.Join(" ", result.Errors),
                    Status = StatusCodes.Status404NotFound
                }),
                _ => new BadRequestObjectResult(new ProblemDetails
                {
                    Title = "Bad Request",
                    Detail = string.Join(" ", result.Errors),
                    Status = StatusCodes.Status400BadRequest
                })
            };
        }

        public static IActionResult ToActionResult<T>(this OperationResult<T> result, ILogger logger)
        {
            if (result.IsSuccess)
            {
                logger.LogInformation("Request succeeded with data: {Data}", result.Data);
                return new OkObjectResult(result.Data);
            }

            var errorMessage = result.Errors.FirstOrDefault() ?? "An error occurred";

            logger.LogWarning("Request failed with errors: {Errors}", string.Join(" ", result.Errors));
            return errorMessage switch
            {
                "Invalid access token" => new UnauthorizedObjectResult(new ProblemDetails
                {
                    Title = "Unauthorized",
                    Detail = string.Join(" ", result.Errors),
                    Status = StatusCodes.Status401Unauthorized
                }),
                "User not found" => new NotFoundObjectResult(new ProblemDetails
                {
                    Title = "Not Found",
                    Detail = string.Join(" ", result.Errors),
                    Status = StatusCodes.Status404NotFound
                }),
                _ => new BadRequestObjectResult(new ProblemDetails
                {
                    Title = "Bad Request",
                    Detail = string.Join(" ", result.Errors),
                    Status = StatusCodes.Status400BadRequest
                })
            };
        }
    }
}
