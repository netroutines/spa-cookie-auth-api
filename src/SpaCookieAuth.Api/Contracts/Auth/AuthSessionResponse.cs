namespace SpaCookieAuth.Api.Contracts.Auth;

public sealed record AuthSessionResponse(
    bool Authenticated,
    AuthenticatedUserResponse? User);
