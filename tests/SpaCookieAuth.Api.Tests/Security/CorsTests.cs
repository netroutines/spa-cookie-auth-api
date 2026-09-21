using System.Net;
using SpaCookieAuth.Api.Security;
using SpaCookieAuth.Api.Tests.Infrastructure;

namespace SpaCookieAuth.Api.Tests.Security;

public sealed class CorsTests
{
    private const string AllowedOrigin =
        "https://localhost:5173";

    private const string DisallowedOrigin =
        "https://example.test";

    [Fact]
    public async Task Allowed_origin_receives_cors_headers()
    {
        await using var factory = new ApiWebApplicationFactory();
        using var client = factory.CreateHttpsClient();

        using var request =
            new HttpRequestMessage(
                HttpMethod.Get,
                "/api/auth/session");

        request.Headers.Add(
            "Origin",
            AllowedOrigin);

        using var response =
            await client.SendAsync(request);

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        Assert.Equal(
            AllowedOrigin,
            GetSingleHeader(
                response,
                "Access-Control-Allow-Origin"));

        Assert.Equal(
            "true",
            GetSingleHeader(
                response,
                "Access-Control-Allow-Credentials"));
    }

    [Fact]
    public async Task Disallowed_origin_does_not_receive_cors_headers()
    {
        await using var factory = new ApiWebApplicationFactory();
        using var client = factory.CreateHttpsClient();

        using var request =
            new HttpRequestMessage(
                HttpMethod.Get,
                "/api/auth/session");

        request.Headers.Add(
            "Origin",
            DisallowedOrigin);

        using var response =
            await client.SendAsync(request);

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        Assert.False(
            response.Headers.Contains(
                "Access-Control-Allow-Origin"));

        Assert.False(
            response.Headers.Contains(
                "Access-Control-Allow-Credentials"));
    }

    [Fact]
    public async Task Login_preflight_allows_post_and_required_headers()
    {
        await using var factory = new ApiWebApplicationFactory();
        using var client = factory.CreateHttpsClient();

        using var request =
            new HttpRequestMessage(
                HttpMethod.Options,
                "/api/auth/login");

        request.Headers.Add(
            "Origin",
            AllowedOrigin);

        request.Headers.Add(
            "Access-Control-Request-Method",
            "POST");

        request.Headers.Add(
            "Access-Control-Request-Headers",
            "content-type, x-xsrf-token");

        using var response =
            await client.SendAsync(request);

        Assert.Equal(
            HttpStatusCode.NoContent,
            response.StatusCode);

        Assert.Equal(
            AllowedOrigin,
            GetSingleHeader(
                response,
                "Access-Control-Allow-Origin"));

        Assert.Equal(
            "true",
            GetSingleHeader(
                response,
                "Access-Control-Allow-Credentials"));

        var allowedMethods =
            GetCommaSeparatedHeaderValues(
                response,
                "Access-Control-Allow-Methods");

        Assert.Contains(
            allowedMethods,
            method => string.Equals(
                method,
                "POST",
                StringComparison.OrdinalIgnoreCase));

        var allowedHeaders =
            GetCommaSeparatedHeaderValues(
                response,
                "Access-Control-Allow-Headers");

        Assert.Contains(
            allowedHeaders,
            header => string.Equals(
                header,
                "Content-Type",
                StringComparison.OrdinalIgnoreCase));

        Assert.Contains(
            allowedHeaders,
            header => string.Equals(
                header,
                SecurityConstants.AntiforgeryHeaderName,
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Logout_preflight_allows_antiforgery_header_without_content_type()
    {
        await using var factory = new ApiWebApplicationFactory();
        using var client = factory.CreateHttpsClient();

        using var request =
            new HttpRequestMessage(
                HttpMethod.Options,
                "/api/auth/logout");

        request.Headers.Add(
            "Origin",
            AllowedOrigin);

        request.Headers.Add(
            "Access-Control-Request-Method",
            "POST");

        request.Headers.Add(
            "Access-Control-Request-Headers",
            SecurityConstants.AntiforgeryHeaderName);

        using var response =
            await client.SendAsync(request);

        Assert.Equal(
            HttpStatusCode.NoContent,
            response.StatusCode);

        Assert.Equal(
            AllowedOrigin,
            GetSingleHeader(
                response,
                "Access-Control-Allow-Origin"));

        Assert.Equal(
            "true",
            GetSingleHeader(
                response,
                "Access-Control-Allow-Credentials"));

        var allowedMethods =
            GetCommaSeparatedHeaderValues(
                response,
                "Access-Control-Allow-Methods");

        Assert.Contains(
            allowedMethods,
            method => string.Equals(
                method,
                "POST",
                StringComparison.OrdinalIgnoreCase));

        var allowedHeaders =
            GetCommaSeparatedHeaderValues(
                response,
                "Access-Control-Allow-Headers");

        Assert.Contains(
            allowedHeaders,
            header => string.Equals(
                header,
                SecurityConstants.AntiforgeryHeaderName,
                StringComparison.OrdinalIgnoreCase));
    }

    private static string GetSingleHeader(
        HttpResponseMessage response,
        string headerName)
    {
        var values = response.Headers
            .GetValues(headerName)
            .ToArray();

        Assert.Single(values);

        return values[0];
    }

    private static string[] GetCommaSeparatedHeaderValues(
        HttpResponseMessage response,
        string headerName)
    {
        return response.Headers
            .GetValues(headerName)
            .SelectMany(value =>
                value.Split(
                    ',',
                    StringSplitOptions.RemoveEmptyEntries
                    | StringSplitOptions.TrimEntries))
            .ToArray();
    }
}
