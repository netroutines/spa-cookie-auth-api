using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SpaCookieAuth.Api.Identity;

namespace SpaCookieAuth.Api.Tests;

public sealed class DemoUserSeederTests
{
    [Fact]
    public async Task Demo_user_is_not_created_by_default()
    {
        await using var factory =
            new WebApplicationFactory<Program>();

        await using var scope =
            factory.Services.CreateAsyncScope();

        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();

        var user = await userManager.FindByEmailAsync(
            DemoUserSeeder.Email);

        Assert.Null(user);
    }

    [Fact]
    public async Task SeedAsync_creates_demo_user()
    {
        await using var factory =
            new WebApplicationFactory<Program>();

        await using var scope =
            factory.Services.CreateAsyncScope();

        var seeder = scope.ServiceProvider
            .GetRequiredService<DemoUserSeeder>();

        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();

        await seeder.SeedAsync();

        var user = await userManager.FindByEmailAsync(
            DemoUserSeeder.Email);

        Assert.NotNull(user);
        Assert.Equal(DemoUserSeeder.Email, user.Email);
        Assert.Equal(DemoUserSeeder.Email, user.UserName);
        Assert.True(user.EmailConfirmed);
        Assert.True(user.LockoutEnabled);
    }

    [Fact]
    public async Task SeedAsync_is_idempotent()
    {
        await using var factory =
            new WebApplicationFactory<Program>();

        await using var scope =
            factory.Services.CreateAsyncScope();

        var seeder = scope.ServiceProvider
            .GetRequiredService<DemoUserSeeder>();

        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();

        await seeder.SeedAsync();

        var firstUser = await userManager.FindByEmailAsync(
            DemoUserSeeder.Email);

        await seeder.SeedAsync();

        var secondUser = await userManager.FindByEmailAsync(
            DemoUserSeeder.Email);

        Assert.NotNull(firstUser);
        Assert.NotNull(secondUser);
        Assert.Equal(firstUser.Id, secondUser.Id);
    }
}
