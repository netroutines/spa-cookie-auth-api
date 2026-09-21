using System.Net.Mime;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SpaCookieAuth.Api.Authentication;
using SpaCookieAuth.Api.Contracts.Auth;

namespace SpaCookieAuth.Api.Controllers;

[ApiController]
[Route("api/auth")]
[ResponseCache(
    NoStore = true,
    Location = ResponseCacheLocation.None)]
public sealed class AuthController(
    IAuthService authService,
    IAntiforgery antiforgery)
    : ControllerBase
{
    [HttpGet("csrf")]
    [AllowAnonymous]
    [ProducesResponseType<CsrfTokenResponse>(
        StatusCodes.Status200OK,
        MediaTypeNames.Application.Json)]
    public ActionResult<CsrfTokenResponse> Csrf()
    {
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);

        var requestToken = tokens.RequestToken
            ?? throw new InvalidOperationException(
                "Antiforgery request token was not generated");

        return Ok(new CsrfTokenResponse(requestToken));
    }

    [HttpPost("login")]
    [AllowAnonymous]
    [Consumes(MediaTypeNames.Application.Json)]
    [ProducesResponseType<AuthenticatedUserResponse>(
        StatusCodes.Status200OK,
        MediaTypeNames.Application.Json)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<AuthenticatedUserResponse>> Login(
        LoginRequest request)
    {
        var user = await authService.LoginAsync(
            request.Email,
            request.Password);

        return user is null
            ? Unauthorized()
            : Ok(user);
    }

    [HttpGet("session")]
    [AllowAnonymous]
    [ProducesResponseType<AuthSessionResponse>(
        StatusCodes.Status200OK,
        MediaTypeNames.Application.Json)]
    public async Task<ActionResult<AuthSessionResponse>> Session()
    {
        if (User.Identity?.IsAuthenticated != true)
        {
            return Ok(new AuthSessionResponse(
                false,
                null));
        }

        var user = await authService.GetCurrentUserAsync(User);

        return user is null
            ? Ok(new AuthSessionResponse(false, null))
            : Ok(new AuthSessionResponse(true, user));
    }

    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Logout()
    {
        await authService.LogoutAsync();

        return NoContent();
    }
}
