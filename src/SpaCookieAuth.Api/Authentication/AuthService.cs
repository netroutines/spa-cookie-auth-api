using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using SpaCookieAuth.Api.Contracts.Auth;
using SpaCookieAuth.Api.Identity;

namespace SpaCookieAuth.Api.Authentication;

public sealed class AuthService(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager)
    : IAuthService
{
    public async Task<AuthenticatedUserResponse?> LoginAsync(
        string email,
        string password)
    {
        var trimmedEmail = email.Trim();

        var user = await userManager.FindByEmailAsync(trimmedEmail);

        if (user is null)
        {
            return null;
        }

        var result = await signInManager.PasswordSignInAsync(
            user,
            password,
            isPersistent: false,
            lockoutOnFailure: true);

        return result.Succeeded
            ? CreateResponse(user)
            : null;
    }

    public async Task<AuthenticatedUserResponse?> GetCurrentUserAsync(
        ClaimsPrincipal principal)
    {
        var user = await userManager.GetUserAsync(principal);

        return user is null
            ? null
            : CreateResponse(user);
    }

    public Task LogoutAsync()
    {
        return signInManager.SignOutAsync();
    }

    private static AuthenticatedUserResponse CreateResponse(
        ApplicationUser user)
    {
        var email = user.Email
                    ?? throw new InvalidOperationException(
                        "Authenticated user has no email");

        return new AuthenticatedUserResponse(
            user.Id,
            email);
    }
}
