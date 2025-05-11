namespace AuthCore.Application.DTOs
{
    /// <summary>
    /// Request for login
    /// </summary>
    public record LoginRequest
     {
        /// <summary>
        /// The user's email address
        /// </summary>
        public string Email { get; init; } = string.Empty;

        /// <summary>
        /// The user's password
        /// </summary>
        public string Password { get; init; } = string.Empty;
     };
}
