using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SpaCookieAuth.Api.Authentication;
using SpaCookieAuth.Api.Identity;
using SpaCookieAuth.Api.Persistence;
using SpaCookieAuth.Api.Security;

const string seedDemoUserArgument = "--seed-demo-user";

var seedDemoUser = args.Any(argument =>
    string.Equals(
        argument,
        seedDemoUserArgument,
        StringComparison.OrdinalIgnoreCase));

var applicationArguments = args
    .Where(argument =>
        !string.Equals(
            argument,
            seedDemoUserArgument,
            StringComparison.OrdinalIgnoreCase))
    .ToArray();

var builder = WebApplication.CreateBuilder(applicationArguments);

// Add services to the container.

builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(
        new AutoValidateAntiforgeryTokenAttribute());
});

builder.Services.AddOpenApi();

builder.Services.AddAntiforgery(options =>
{
    options.HeaderName =
        SecurityConstants.AntiforgeryHeaderName;

    options.Cookie.Name =
        SecurityConstants.AntiforgeryCookieName;

    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;

    options.Cookie.SecurePolicy =
        builder.Environment.IsDevelopment()
            ? CookieSecurePolicy.SameAsRequest
            : CookieSecurePolicy.Always;
});

var allowedOrigins =
    builder.Configuration
        .GetSection("Cors:AllowedOrigins")
        .Get<string[]>()
    ?? [];

builder.Services.AddCors(options =>
{
    options.AddPolicy(
        SecurityConstants.SpaCorsPolicyName,
        policy =>
        {
            policy
                .WithOrigins(allowedOrigins)
                .WithMethods(
                    HttpMethods.Get,
                    HttpMethods.Post)
                .AllowAnyHeader()
                .AllowCredentials();
        });
});

var databaseName = $"SpaCookieAuth-{Guid.NewGuid():N}";

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseInMemoryDatabase(databaseName));

builder.Services
    .AddIdentityCore<ApplicationUser>(options =>
    {
        options.User.RequireUniqueEmail = true;

        options.Password.RequiredLength = 12;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireDigit = true;
        options.Password.RequireNonAlphanumeric = true;

        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan =
            TimeSpan.FromMinutes(5);
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager();

builder.Services
    .AddAuthentication(IdentityConstants.ApplicationScheme)
    .AddIdentityCookies();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name =
        SecurityConstants.AuthenticationCookieName;

    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;

    options.Cookie.SecurePolicy =
        builder.Environment.IsDevelopment()
            ? CookieSecurePolicy.SameAsRequest
            : CookieSecurePolicy.Always;

    options.ExpireTimeSpan = TimeSpan.FromHours(2);
    options.SlidingExpiration = false;
});

builder.Services
    .AddAuthorizationBuilder()
    .SetFallbackPolicy(
        new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build());

builder.Services.AddScoped<DemoUserSeeder>();
builder.Services.AddScoped<IAuthService, AuthService>();

var app = builder.Build();

if (seedDemoUser)
{
    await using var scope = app.Services.CreateAsyncScope();

    var seeder = scope.ServiceProvider
        .GetRequiredService<DemoUserSeeder>();

    await seeder.SeedAsync();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseCors(SecurityConstants.SpaCorsPolicyName);

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
