using System.ComponentModel.DataAnnotations;

namespace SpaCookieAuth.Api.Contracts.Auth;

public sealed class LoginRequest
{
    [Required]
    [EmailAddress]
    [MaxLength(256)]
    public required string Email { get; init; }

    [Required]
    [MaxLength(256)]
    public required string Password { get; init; }
}
