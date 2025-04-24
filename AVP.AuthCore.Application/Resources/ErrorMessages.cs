using System.Globalization;
using System.Resources;

namespace AVP.AuthCore.Application.Resources
{
    public class ErrorMessages
    {
        private static readonly ResourceManager ResourceManager = new ResourceManager(
            "AVP.AuthCore.Application.Resources.ErrorMessages",
            typeof(ErrorMessages).Assembly);

        public static string Get(string key, CultureInfo? culture = null)
        {
            return ResourceManager.GetString(key, culture ?? CultureInfo.CurrentUICulture) ?? key;
        }
    }
}
