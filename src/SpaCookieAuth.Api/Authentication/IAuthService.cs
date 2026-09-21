using System.Security.Claims;
using SpaCookieAuth.Api.Contracts.Auth;

namespace SpaCookieAuth.Api.Authentication;

public interface IAuthService
{
    Task<AuthenticatedUserResponse?> LoginAsync(
        string email,
        string password);

    Task<AuthenticatedUserResponse?> GetCurrentUserAsync(
        ClaimsPrincipal principal);

    Task LogoutAsync();
}
