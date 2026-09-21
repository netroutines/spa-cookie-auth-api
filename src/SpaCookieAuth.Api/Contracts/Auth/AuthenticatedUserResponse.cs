namespace SpaCookieAuth.Api.Contracts.Auth;

public sealed record AuthenticatedUserResponse(
    Guid Id,
    string Email);
