namespace AVP.AuthCore.Application.Common.Errors
{
    public static class ErrorCatalog
    {
        private const string Prefix = "error";

        private static readonly Dictionary<ErrorCode, string> Messages = new()
        {
            { ErrorCode.Unknown, $"{Prefix}.unknown" },

            // Authentication Errors (1000-1999)
            { ErrorCode.InvalidAccessToken, $"{Prefix}.invalid_access_token" },
            { ErrorCode.InvalidCredentials, $"{Prefix}.invalid_credentials" },
            { ErrorCode.RefreshTokenExpired, $"{Prefix}.refresh_token_expired" },
            { ErrorCode.RefreshTokenNotFound, $"{Prefix}.refresh_token_not_found" },
            { ErrorCode.RefreshTokenAlreadyRevoked, $"{Prefix}.refresh_token_already_revoked" },
            { ErrorCode.RefreshTokenInvalid, $"{Prefix}.refresh_token_invalid" },
            { ErrorCode.SessionExpired, $"{Prefix}.session_expired" },
            { ErrorCode.ConcurrentLogin, $"{Prefix}.concurrent_login" },

            // User Management Errors (2000-2999)
            { ErrorCode.UserNotFound, $"{Prefix}.user_not_found" },
            { ErrorCode.UserAlreadyExists, $"{Prefix}.user_already_exists" },
            { ErrorCode.UserLocked, $"{Prefix}.user_locked" },
            { ErrorCode.UserDisabled, $"{Prefix}.user_disabled" },
            { ErrorCode.EmailNotConfirmed, $"{Prefix}.email_not_confirmed" },
            { ErrorCode.EmailAlreadyConfirmed, $"{Prefix}.email_already_confirmed" },
            { ErrorCode.InvalidEmailConfirmationToken, $"{Prefix}.invalid_email_confirmation_token" },
            { ErrorCode.InvalidPasswordResetToken, $"{Prefix}.invalid_password_reset_token" },

            // Registration Errors (3000-3999)
            { ErrorCode.RegistrationFailed, $"{Prefix}.registration_failed" },
            { ErrorCode.InvalidEmail, $"{Prefix}.invalid_email" },
            { ErrorCode.InvalidUsername, $"{Prefix}.invalid_username" },

            // Password Validation Errors (4000-4999)
            { ErrorCode.PasswordRequiresDigit, $"{Prefix}.password_requires_digit" },
            { ErrorCode.PasswordRequiresNonAlphanumeric, $"{Prefix}.password_requires_non_alphanumeric" },
            { ErrorCode.PasswordRequiresUpper, $"{Prefix}.password_requires_upper" },
            { ErrorCode.PasswordRequiresLower, $"{Prefix}.password_requires_lower" },
            { ErrorCode.PasswordContainsPersonalData, $"{Prefix}.password_contains_personal_data" },

            // Role Management Errors (5000-5999)
            { ErrorCode.RoleNotFound, $"{Prefix}.role_not_found" },
            { ErrorCode.UserAlreadyInRole, $"{Prefix}.user_already_in_role" },
            { ErrorCode.UserNotInRole, $"{Prefix}.user_not_in_role" },
            { ErrorCode.DefaultRoleNotFound, $"{Prefix}.default_role_not_found" },

            // External Authentication Errors (6000-6999)
            { ErrorCode.ExternalAuthenticationError, $"{Prefix}.external_authentication_error" },
            { ErrorCode.ExternalProviderNotFound, $"{Prefix}.external_provider_not_found" },
            { ErrorCode.ExternalUserAlreadyAssociated, $"{Prefix}.external_user_already_associated" },

            // General Validation Errors (7000-7999)
            { ErrorCode.ValidationFailed, $"{Prefix}.validation_failed" },
            { ErrorCode.InvalidRequest, $"{Prefix}.invalid_request" },
            { ErrorCode.InvalidOperation, $"{Prefix}.invalid_operation" },

            // Infrastructure Errors (8000-8999)
            { ErrorCode.DatabaseError, $"{Prefix}.database_error" },
            { ErrorCode.CommunicationError, $"{Prefix}.communication_error" },
            { ErrorCode.ConfigurationError, $"{Prefix}.configuration_error" },

            // Rate Limiting Errors (9000-9999)
            { ErrorCode.TooManyRequests, $"{Prefix}.too_many_requests" },
            { ErrorCode.TooManyFailedAttempts, $"{Prefix}.too_many_failed_attempts" },

            // Two-Factor Authentication Errors (10000-10999)
            { ErrorCode.TwoFactorRequired, $"{Prefix}.two_factor_required" },
            { ErrorCode.InvalidTwoFactorCode, $"{Prefix}.invalid_two_factor_code" },
            { ErrorCode.TwoFactorAlreadyEnabled, $"{Prefix}.two_factor_already_enabled" },
            { ErrorCode.TwoFactorNotEnabled, $"{Prefix}.two_factor_not_enabled" },
            { ErrorCode.InvalidRecoveryCode, $"{Prefix}.invalid_recovery_code" },
        };

        public static string GetMessageKey(ErrorCode code)
        {
            return Messages.GetValueOrDefault(code, $"{Prefix}.unknown");
        }
    }
}
