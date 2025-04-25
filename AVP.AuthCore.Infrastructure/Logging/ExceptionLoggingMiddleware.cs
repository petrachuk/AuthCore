using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text.Json;

namespace AVP.AuthCore.Infrastructure.Logging
{
    /// <summary>
    /// Перехватывает все необработанные исключения в приложении
    /// </summary>
    public class ExceptionLoggingMiddleware(RequestDelegate next, ILogger<ExceptionLoggingMiddleware> logger)
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true // или true, если нужно читаемое форматирование
        };

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await next(context);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unhandled exception");

                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                context.Response.ContentType = "application/problem+json";

                var problemDetails = new ProblemDetails
                {
                    Type = "https://tools.ietf.org/html/rfc7231#section-6.5.1",
                    Title = "Internal Server Error",
                    Status = StatusCodes.Status500InternalServerError,
                    Detail = ex.Message,
                    Instance = context.Request.Path,
                    Extensions =
                    {
                        ["traceId"] = context.TraceIdentifier
                    }
                };

#if DEBUG
                // В режиме отладки можно включить стектрейс
                problemDetails.Extensions["stackTrace"] = ex.StackTrace;
#endif

                var json = JsonSerializer.Serialize(problemDetails, JsonOptions);
                await context.Response.WriteAsync(json);
            }
        }
    }
}
