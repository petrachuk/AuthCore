﻿using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using AuthCore.Application.Common.Results;
using AuthCore.Application.Common.Errors;

namespace AuthCore.API.Extensions
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
            var problemDetails = new ProblemDetails
            {
                Type = "https://tools.ietf.org/html/rfc7231#section-6.5.1",
                Detail = details?.FirstOrDefault()?.Description,
                Instance = httpContext.Request.Path,
                Extensions = {
                    ["errors"] = details,
                    ["traceId"] = httpContext.TraceIdentifier
                }
            };

            return error switch
            {
                ErrorCode.InvalidAccessToken or ErrorCode.RefreshTokenExpired or ErrorCode.InvalidCredentials => SetProblemResult(problemDetails, "Unauthorized", StatusCodes.Status401Unauthorized),
                ErrorCode.UserNotFound => SetProblemResult(problemDetails, "Not Found", StatusCodes.Status404NotFound),
                ErrorCode.UserAlreadyExists => SetProblemResult(problemDetails, "UserAlreadyExists", StatusCodes.Status409Conflict),
                ErrorCode.RefreshTokenNotFound => SetProblemResult(problemDetails, "RefreshTokenNotFound", StatusCodes.Status403Forbidden),
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
                StatusCodes.Status409Conflict => new ConflictObjectResult(problem),
                StatusCodes.Status403Forbidden => new ObjectResult(problem)
                    { StatusCode = StatusCodes.Status403Forbidden },
                _ => new BadRequestObjectResult(problem)
            };
        }
    }
}
