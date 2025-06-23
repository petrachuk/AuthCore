namespace AuthCore.Application.DTOs
{
    /// <summary>
    /// Request for user registration
    /// </summary>
    public record RegisterRequest
    {
        /// <summary>
        /// The type of identifier used for registration
        /// </summary>
        public IdentityType IdentityType { get; init; }

        /// <summary>
        /// The identifier value (email, phone, messenger ID)
        /// </summary>
        public string Identifier { get; init; } = string.Empty;


        /// <summary>
        /// The user's password (if applicable for this registration type)
        /// </summary>
        public string? Password { get; init; }
    }
}
