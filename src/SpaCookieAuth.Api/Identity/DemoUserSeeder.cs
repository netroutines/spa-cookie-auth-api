using Microsoft.AspNetCore.Identity;

namespace SpaCookieAuth.Api.Identity;

public sealed class DemoUserSeeder(
    UserManager<ApplicationUser> userManager,
    ILogger<DemoUserSeeder> logger)
{
    public const string Email = "user@demo.test";
    public const string Password = "DemoPassword1!";

    public async Task SeedAsync()
    {
        var existingUser = await userManager.FindByEmailAsync(Email);

        if (existingUser is not null)
        {
            if (logger.IsEnabled(LogLevel.Information))
            {
                logger.LogInformation(
                    "Demo user {Email} already exists",
                    Email);
            }

            return;
        }

        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = Email,
            Email = Email,
            EmailConfirmed = true,
            LockoutEnabled = true
        };

        var result = await userManager.CreateAsync(
            user,
            Password);

        if (!result.Succeeded)
        {
            var errors = string.Join(
                "; ",
                result.Errors.Select(error => error.Description));

            throw new InvalidOperationException(
                $"Could not create demo user: {errors}");
        }

        if (logger.IsEnabled(LogLevel.Information))
        {
            logger.LogInformation(
                "Demo user created: {Email}",
                Email);
        }
    }
}
