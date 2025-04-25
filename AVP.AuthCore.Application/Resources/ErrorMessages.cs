using System.Globalization;
using System.Resources;

namespace AVP.AuthCore.Application.Resources
{
    public class ErrorMessages
    {
        private static readonly ResourceManager ResourceManager = new(
            "AVP.AuthCore.Application.Resources.ErrorMessages",
            typeof(ErrorMessages).Assembly);

        public static string Get(string key, CultureInfo? culture = null, params object[] args)
        {
            var message = ResourceManager.GetString(key, culture ?? CultureInfo.CurrentUICulture) ?? key;
            return args.Length > 0 ? string.Format(message, args) : message;
        }
    }
}
