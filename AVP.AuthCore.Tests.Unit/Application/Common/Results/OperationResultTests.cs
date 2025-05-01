using AVP.AuthCore.Application.Common.Results;
using AVP.AuthCore.Application.Common.Errors;
using Microsoft.AspNetCore.Identity;
using Xunit;

namespace AVP.AuthCore.Tests.Unit.Application.Common.Results
{
    public class OperationResultTests
    {
        [Fact]
        public void Ok_Should_Return_Successful_Result()
        {
            // Act
            var result = OperationResult.Ok();

            // Assert
            Assert.True(result.IsSuccess);
            Assert.False(result.IsCreated);
            Assert.Null(result.Error);
            Assert.Equal(result?.Details?.Count(), 0);
        }

        [Fact]
        public void Ok_With_IsCreated_Should_Return_Successful_Result_With_IsCreated()
        {
            // Act
            var result = OperationResult.Ok(isCreated: true);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.IsCreated);
            Assert.Null(result.Error);
            Assert.Equal(result?.Details?.Count(), 0);
        }

        [Fact]
        public void Fail_Should_Return_Failed_Result_With_ErrorCode()
        {
            // Arrange
            var errorCode = ErrorCode.InvalidCredentials;

            // Act
            var result = OperationResult.Fail(errorCode);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(errorCode, result.Error);
            Assert.Equal(result?.Details?.Count(), 0);
        }

        [Fact]
        public void Fail_With_Details_Should_Return_Failed_Result_With_ErrorCode_And_Details()
        {
            // Arrange
            var errorCode = ErrorCode.InvalidCredentials;
            var details = new List<IdentityError>
            {
                new IdentityError { Code = "PasswordTooShort", Description = "Password must be at least 6 characters long." }
            };

            // Act
            var result = OperationResult.Fail(errorCode, details);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(errorCode, result.Error);
            Assert.Equal(details, result.Details);
        }
    }

    public class OperationResultGenericTests
    {
        [Fact]
        public void Ok_Should_Return_Successful_Result_With_Data()
        {
            // Arrange
            var data = "TestData";

            // Act
            var result = OperationResult<string>.Ok(data);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.False(result.IsCreated);
            Assert.Equal(data, result.Data);
            Assert.Null(result.Error);
            Assert.Equal(result?.Details?.Count(), 0);
        }

        [Fact]
        public void Ok_With_IsCreated_Should_Return_Successful_Result_With_Data_And_IsCreated()
        {
            // Arrange
            var data = "TestData";

            // Act
            var result = OperationResult<string>.Ok(data, isCreated: true);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.IsCreated);
            Assert.Equal(data, result.Data);
            Assert.Null(result.Error);
            Assert.Equal(result?.Details?.Count(), 0);
        }

        [Fact]
        public void Fail_Should_Return_Failed_Result_With_ErrorCode()
        {
            // Arrange
            var errorCode = ErrorCode.UserNotFound;

            // Act
            var result = OperationResult<string>.Fail(errorCode);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(errorCode, result.Error);
            Assert.Null(result.Data);
            Assert.Equal(result?.Details?.Count(), 0);
        }

        [Fact]
        public void Fail_With_Details_Should_Return_Failed_Result_With_ErrorCode_And_Details()
        {
            // Arrange
            var errorCode = ErrorCode.UserNotFound;
            var details = new List<IdentityError>
            {
                new IdentityError { Code = "UserNotFound", Description = "The user does not exist." }
            };

            // Act
            var result = OperationResult<string>.Fail(errorCode, details);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(errorCode, result.Error);
            Assert.Null(result.Data);
            Assert.Equal(details, result.Details);
        }
    }
}
