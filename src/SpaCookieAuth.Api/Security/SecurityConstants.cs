namespace SpaCookieAuth.Api.Security;

public static class SecurityConstants
{
    public const string AuthenticationCookieName = ".SpaCookieAuth.Auth";
    public const string AntiforgeryCookieName = ".SpaCookieAuth.Antiforgery";
    public const string AntiforgeryHeaderName = "X-XSRF-TOKEN";
}
