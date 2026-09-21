using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SpaCookieAuth.Api.Identity;

namespace SpaCookieAuth.Api.Persistence;

public sealed class ApplicationDbContext(
    DbContextOptions<ApplicationDbContext> options)
    : IdentityUserContext<ApplicationUser, Guid>(options);
