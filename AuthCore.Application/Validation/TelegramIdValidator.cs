using System.Text.RegularExpressions;

namespace AuthCore.Application.Validation
{
    public static partial class TelegramIdValidator
    {
        public static bool IsValid(string id)
        {
            // Telegram ID can be numeric or username
            return !string.IsNullOrEmpty(id) && (
                // Numeric ID
                long.TryParse(id, out _) ||
                // Username (without @, 5-32 chars, letters, numbers and underscores)
                TelegramUsernameRegex().IsMatch(id)
            );
        }

        [GeneratedRegex(@"^[a-zA-Z0-9_]{5,32}$")]
        private static partial Regex TelegramUsernameRegex();
    }
}
