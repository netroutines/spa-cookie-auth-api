using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SpaCookieAuth.Api.Identity;

namespace SpaCookieAuth.Api.Tests.Infrastructure;

internal sealed class ApiWebApplicationFactory
    : WebApplicationFactory<Program>
{
    public HttpClient CreateHttpsClient()
    {
        return CreateClient(
            new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                BaseAddress = new Uri("https://localhost"),
                HandleCookies = true
            });
    }

    public async Task SeedDemoUserAsync()
    {
        await using var scope = Services.CreateAsyncScope();

        var seeder = scope.ServiceProvider
            .GetRequiredService<DemoUserSeeder>();

        await seeder.SeedAsync();
    }
}
