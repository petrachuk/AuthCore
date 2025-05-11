using System.ComponentModel;

namespace AuthCore.Application.Common.Errors
{
    public enum ErrorCode
    {
        Unknown = 0,

        // Authentication Errors (1000-1999)
        [Description("Invalid access token")]
        InvalidAccessToken = 1000,
        InvalidCredentials = 1001,
        RefreshTokenExpired = 1002,
        RefreshTokenNotFound = 1003,
        RefreshTokenAlreadyRevoked = 1004,
        RefreshTokenInvalid = 1005,
        SessionExpired = 1006,
        ConcurrentLogin = 1007,

        // User Management Errors (2000-2999)
        UserNotFound = 2000,
        UserAlreadyExists = 2001,
        UserLocked = 2002,
        UserDisabled = 2003,
        EmailNotConfirmed = 2004,
        EmailAlreadyConfirmed = 2005,
        InvalidEmailConfirmationToken = 2006,
        InvalidPasswordResetToken = 2007,

        // Registration Errors (3000-3999)
        RegistrationFailed = 3000,
        InvalidEmail = 3001,
        InvalidUsername = 3002,

        // Password Validation Errors (4000-4999)
        PasswordRequiresDigit = 4000,
        PasswordRequiresNonAlphanumeric = 4001,
        PasswordRequiresUpper = 4002,
        PasswordRequiresLower = 4003,
        PasswordTooShort = 4004,
        PasswordRequiresUniqueChars = 4005,
        PasswordContainsPersonalData = 4006,

        // Role Management Errors (5000-5999)
        RoleNotFound = 5000,
        UserAlreadyInRole = 5001,
        UserNotInRole = 5002,
        DefaultRoleNotFound = 5003,

        // External Authentication Errors (6000-6999)
        ExternalAuthenticationError = 6000,
        ExternalProviderNotFound = 6001,
        ExternalUserAlreadyAssociated = 6002,

        // General Validation Errors (7000-7999)
        ValidationFailed = 7000,
        InvalidRequest = 7001,
        InvalidOperation = 7002,

        // Infrastructure Errors (8000-8999)
        DatabaseError = 8000,
        CommunicationError = 8001,
        ConfigurationError = 8002,

        // Rate Limiting Errors (9000-9999)
        TooManyRequests = 9000,
        TooManyFailedAttempts = 9001,

        // Two-Factor Authentication Errors (10000-10999)
        TwoFactorRequired = 10000,
        InvalidTwoFactorCode = 10001,
        TwoFactorAlreadyEnabled = 10002,
        TwoFactorNotEnabled = 10003,
        InvalidRecoveryCode = 10004
    }
}
