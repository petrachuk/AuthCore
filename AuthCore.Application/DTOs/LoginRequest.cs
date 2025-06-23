namespace AuthCore.Application.DTOs
{
    /// <summary>
    /// Request for login
    /// </summary>
    public record LoginRequest
     {
        /// <summary>
        /// The type of identifier used for login
        /// </summary>
        public IdentityType IdentityType { get; init; }

        /// <summary>
        /// The identifier value (email, phone, messenger ID)
        /// </summary>
        public string Identifier { get; init; } = string.Empty;

        /// <summary>
        /// The user's password (if applicable for this login type)
        /// </summary>
        public string? Password { get; init; }
    };
}
