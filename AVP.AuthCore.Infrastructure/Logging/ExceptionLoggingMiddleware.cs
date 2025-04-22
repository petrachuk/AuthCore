using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;

namespace AVP.AuthCore.Infrastructure.Logging
{
    /// <summary>
    /// Перехватывает все необработанные исключения в приложении
    /// </summary>
    /// <param name="next"></param>
    /// <param name="logger">Логгер</param>
    public class ExceptionLoggingMiddleware(RequestDelegate next, ILogger<ExceptionLoggingMiddleware> logger)
    {
        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await next(context);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An unhandled exception occurred during the request.");
                throw; // Re-throw the exception to let the global error handler handle it
            }
        }
    }
}
