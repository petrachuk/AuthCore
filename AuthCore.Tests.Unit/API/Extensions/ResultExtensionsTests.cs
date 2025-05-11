using AuthCore.API.Extensions;
using AuthCore.Application.Common.Errors;
using AuthCore.Application.Common.Results;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;

namespace AuthCore.Tests.Unit.API.Extensions
{
    public class ResultExtensionsTests
    {
        private readonly Mock<ILogger> _loggerMock;
        private readonly Mock<HttpContext> _httpContextMock;

        public ResultExtensionsTests()
        {
            _loggerMock = new Mock<ILogger>();
            _httpContextMock = new Mock<HttpContext>();
            _httpContextMock.SetupGet(x => x.Request.Path).Returns("/test-path");
            _httpContextMock.SetupGet(x => x.TraceIdentifier).Returns("trace-id-123");
        }

        [Fact]
        public void ToActionResult_Should_Return_NoContentResult_When_OperationResult_Is_Success()
        {
            // Arrange
            var result = OperationResult.Ok();

            // Act
            var actionResult = result.ToActionResult(_loggerMock.Object, _httpContextMock.Object);

            // Assert
            Assert.IsType<NoContentResult>(actionResult);
            _loggerMock.Verify(
                x => x.Log(
                    LogLevel.Information,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("Request succeeded")),
                    It.IsAny<Exception>(),
                    It.IsAny<Func<It.IsAnyType, Exception, string>>()
                ),
                Times.Once
            );
        }

        [Fact]
        public void ToActionResult_Should_Return_Status201Created_When_OperationResult_Is_Success_And_IsCreated()
        {
            // Arrange
            var result = OperationResult.Ok(isCreated: true);

            // Act
            var actionResult = result.ToActionResult(_loggerMock.Object, _httpContextMock.Object);

            // Assert
            Assert.IsType<StatusCodeResult>(actionResult);
            Assert.Equal(StatusCodes.Status201Created, ((StatusCodeResult)actionResult).StatusCode);
            _loggerMock.Verify(
                x => x.Log(
                    LogLevel.Information,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("Request succeeded")),
                    It.IsAny<Exception>(),
                    It.IsAny<Func<It.IsAnyType, Exception?, string>>()
                ),
                Times.Once
            );

        }

        [Fact]
        public void ToActionResult_Should_Return_BadRequestObjectResult_When_OperationResult_Fails_With_Unknown_Error()
        {
            // Arrange
            var result = OperationResult.Fail(ErrorCode.Unknown);

            // Act
            var actionResult = result.ToActionResult(_loggerMock.Object, _httpContextMock.Object);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(actionResult);
            var problemDetails = Assert.IsType<ProblemDetails>(badRequestResult.Value);
            Assert.Equal("Bad Request", problemDetails.Title);
            Assert.Equal(StatusCodes.Status400BadRequest, problemDetails.Status);
            Assert.Equal("/test-path", problemDetails.Instance);
            Assert.Equal("trace-id-123", problemDetails.Extensions["traceId"]);
        }

        [Fact]
        public void ToActionResult_Should_Return_UnauthorizedObjectResult_When_OperationResult_Fails_With_InvalidAccessToken()
        {
            // Arrange
            var result = OperationResult.Fail(ErrorCode.InvalidAccessToken);

            // Act
            var actionResult = result.ToActionResult(_loggerMock.Object, _httpContextMock.Object);

            // Assert
            var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(actionResult);
            var problemDetails = Assert.IsType<ProblemDetails>(unauthorizedResult.Value);
            Assert.Equal("Unauthorized", problemDetails.Title);
            Assert.Equal(StatusCodes.Status401Unauthorized, problemDetails.Status);
        }

        [Fact]
        public void ToActionResult_Should_Return_NotFoundObjectResult_When_OperationResult_Fails_With_UserNotFound()
        {
            // Arrange
            var result = OperationResult.Fail(ErrorCode.UserNotFound);

            // Act
            var actionResult = result.ToActionResult(_loggerMock.Object, _httpContextMock.Object);

            // Assert
            var notFoundResult = Assert.IsType<NotFoundObjectResult>(actionResult);
            var problemDetails = Assert.IsType<ProblemDetails>(notFoundResult.Value);
            Assert.Equal("Not Found", problemDetails.Title);
            Assert.Equal(StatusCodes.Status404NotFound, problemDetails.Status);
        }

        [Fact]
        public void ToActionResult_Generic_Should_Return_OkObjectResult_With_Data_When_OperationResult_Is_Success()
        {
            // Arrange
            var data = "TestData";
            var result = OperationResult<string>.Ok(data);

            // Act
            var actionResult = result.ToActionResult(_loggerMock.Object, _httpContextMock.Object);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(actionResult);
            Assert.Equal(data, okResult.Value);
            _loggerMock.Verify(
                x => x.Log(
                    LogLevel.Information,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("Request succeeded with data: TestData")),
                    null,
                    It.IsAny<Func<It.IsAnyType, Exception?, string>>()
                ),
                Times.Once
            );

        }

        [Fact]
        public void ToActionResult_Generic_Should_Return_Status201Created_With_Data_When_OperationResult_Is_Success_And_IsCreated()
        {
            // Arrange
            var data = "TestData";
            var result = OperationResult<string>.Ok(data, isCreated: true);

            // Act
            var actionResult = result.ToActionResult(_loggerMock.Object, _httpContextMock.Object);

            // Assert
            var createdResult = Assert.IsType<ObjectResult>(actionResult);
            Assert.Equal(StatusCodes.Status201Created, createdResult.StatusCode);
            Assert.Equal(data, createdResult.Value);
        }

        [Fact]
        public void ToActionResult_Generic_Should_Return_BadRequestObjectResult_When_OperationResult_Fails()
        {
            // Arrange
            var result = OperationResult<string>.Fail(ErrorCode.InvalidRequest);

            // Act
            var actionResult = result.ToActionResult(_loggerMock.Object, _httpContextMock.Object);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(actionResult);
            var problemDetails = Assert.IsType<ProblemDetails>(badRequestResult.Value);
            Assert.Equal("Bad Request", problemDetails.Title);
            Assert.Equal(StatusCodes.Status400BadRequest, problemDetails.Status);
        }
    }
}
