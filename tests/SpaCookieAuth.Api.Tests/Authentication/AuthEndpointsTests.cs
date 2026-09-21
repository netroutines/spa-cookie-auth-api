using System.Net;
using System.Net.Http.Json;
using System.Net.Mime;
using SpaCookieAuth.Api.Contracts.Auth;
using SpaCookieAuth.Api.Identity;
using SpaCookieAuth.Api.Security;
using SpaCookieAuth.Api.Tests.Infrastructure;

namespace SpaCookieAuth.Api.Tests.Authentication;

public sealed class AuthEndpointsTests
{
    [Fact]
    public async Task Session_returns_unauthenticated_for_anonymous_user()
    {
        await using var factory = new ApiWebApplicationFactory();
        using var client = factory.CreateHttpsClient();

        using var response = await client.GetAsync("/api/auth/session");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(true, response.Headers.CacheControl?.NoStore);
        Assert.Equal(
            MediaTypeNames.Application.Json,
            response.Content.Headers.ContentType?.MediaType);

        var session =
            await response.Content.ReadFromJsonAsync<AuthSessionResponse>();

        Assert.NotNull(session);
        Assert.False(session.Authenticated);
        Assert.Null(session.User);
    }

    [Fact]
    public async Task Csrf_returns_token_and_secure_antiforgery_cookie()
    {
        await using var factory = new ApiWebApplicationFactory();
        using var client = factory.CreateHttpsClient();

        using var response = await client.GetAsync("/api/auth/csrf");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(true, response.Headers.CacheControl?.NoStore);

        var payload =
            await response.Content.ReadFromJsonAsync<CsrfTokenResponse>();

        Assert.NotNull(payload);
        Assert.False(string.IsNullOrWhiteSpace(payload.Token));

        var cookie = GetCookie(
            response,
            SecurityConstants.AntiforgeryCookieName);

        var normalizedCookie = cookie.ToLowerInvariant();

        Assert.Contains("path=/", normalizedCookie);
        Assert.Contains("secure", normalizedCookie);
        Assert.Contains("httponly", normalizedCookie);
        Assert.Contains("samesite=lax", normalizedCookie);
    }

    [Fact]
    public async Task Login_without_csrf_token_returns_bad_request()
    {
        await using var factory = new ApiWebApplicationFactory();
        await factory.SeedDemoUserAsync();

        using var client = factory.CreateHttpsClient();

        using var response = await PostLoginAsync(
            client,
            csrfToken: null,
            DemoUserSeeder.Email,
            DemoUserSeeder.Password);

        Assert.Equal(
            HttpStatusCode.BadRequest,
            response.StatusCode);
    }

    [Fact]
    public async Task Login_with_invalid_credentials_returns_unauthorized()
    {
        await using var factory = new ApiWebApplicationFactory();
        await factory.SeedDemoUserAsync();

        using var client = factory.CreateHttpsClient();

        var csrfToken = await GetCsrfTokenAsync(client);

        using var response = await PostLoginAsync(
            client,
            csrfToken,
            DemoUserSeeder.Email,
            "WrongPassword1!");

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);
    }

    [Fact]
    public async Task Login_sets_secure_session_cookie_and_authenticates_session()
    {
        await using var factory = new ApiWebApplicationFactory();
        await factory.SeedDemoUserAsync();

        using var client = factory.CreateHttpsClient();

        var csrfToken = await GetCsrfTokenAsync(client);

        using var loginResponse = await PostLoginAsync(
            client,
            csrfToken,
            DemoUserSeeder.Email,
            DemoUserSeeder.Password);

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var user =
            await loginResponse.Content
                .ReadFromJsonAsync<AuthenticatedUserResponse>();

        Assert.NotNull(user);
        Assert.Equal(DemoUserSeeder.Email, user.Email);

        var cookie = GetCookie(
            loginResponse,
            SecurityConstants.AuthenticationCookieName);

        var normalizedCookie = cookie.ToLowerInvariant();

        Assert.Contains("path=/", normalizedCookie);
        Assert.Contains("secure", normalizedCookie);
        Assert.Contains("httponly", normalizedCookie);
        Assert.Contains("samesite=lax", normalizedCookie);

        Assert.DoesNotContain("expires=", normalizedCookie);
        Assert.DoesNotContain("max-age=", normalizedCookie);

        using var sessionResponse =
            await client.GetAsync("/api/auth/session");

        Assert.Equal(
            HttpStatusCode.OK,
            sessionResponse.StatusCode);

        var session =
            await sessionResponse.Content
                .ReadFromJsonAsync<AuthSessionResponse>();

        Assert.NotNull(session);
        Assert.True(session.Authenticated);
        Assert.NotNull(session.User);
        Assert.Equal(user.Id, session.User.Id);
        Assert.Equal(DemoUserSeeder.Email, session.User.Email);
    }

    [Fact]
    public async Task Login_with_invalid_csrf_token_returns_bad_request()
    {
        await using var factory = new ApiWebApplicationFactory();
        await factory.SeedDemoUserAsync();

        using var client = factory.CreateHttpsClient();

        _ = await GetCsrfTokenAsync(client);

        using var response = await PostLoginAsync(
            client,
            "invalid-csrf-token",
            DemoUserSeeder.Email,
            DemoUserSeeder.Password);

        Assert.Equal(
            HttpStatusCode.BadRequest,
            response.StatusCode);
    }

    [Fact]
    public async Task Login_with_unknown_email_returns_unauthorized()
    {
        await using var factory = new ApiWebApplicationFactory();
        using var client = factory.CreateHttpsClient();

        var csrfToken = await GetCsrfTokenAsync(client);

        using var response = await PostLoginAsync(
            client,
            csrfToken,
            "missing@demo.test",
            DemoUserSeeder.Password);

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);
    }

    [Fact]
    public async Task Login_with_invalid_request_returns_bad_request()
    {
        await using var factory = new ApiWebApplicationFactory();
        using var client = factory.CreateHttpsClient();

        var csrfToken = await GetCsrfTokenAsync(client);

        using var request =
            new HttpRequestMessage(
                HttpMethod.Post,
                "/api/auth/login")
            {
                Content = JsonContent.Create(
                    new
                    {
                        email = "not-an-email",
                        password = ""
                    })
            };

        request.Headers.Add(
            SecurityConstants.AntiforgeryHeaderName,
            csrfToken);

        using var response = await client.SendAsync(request);

        Assert.Equal(
            HttpStatusCode.BadRequest,
            response.StatusCode);
    }

    [Fact]
    public async Task Login_locks_user_out_after_maximum_failed_attempts()
    {
        await using var factory = new ApiWebApplicationFactory();
        await factory.SeedDemoUserAsync();

        using var client = factory.CreateHttpsClient();

        var csrfToken = await GetCsrfTokenAsync(client);

        for (var attempt = 0; attempt < 5; attempt++)
        {
            using var failedResponse = await PostLoginAsync(
                client,
                csrfToken,
                DemoUserSeeder.Email,
                "WrongPassword1!");

            Assert.Equal(
                HttpStatusCode.Unauthorized,
                failedResponse.StatusCode);
        }

        using var lockedOutResponse = await PostLoginAsync(
            client,
            csrfToken,
            DemoUserSeeder.Email,
            DemoUserSeeder.Password);

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            lockedOutResponse.StatusCode);
    }

    [Fact]
    public async Task Logout_without_authentication_returns_unauthorized()
    {
        await using var factory = new ApiWebApplicationFactory();
        using var client = factory.CreateHttpsClient();

        using var response =
            await client.PostAsync("/api/auth/logout", content: null);

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);
    }

    [Fact]
    public async Task Logout_clears_authenticated_session()
    {
        await using var factory = new ApiWebApplicationFactory();
        await factory.SeedDemoUserAsync();

        using var client = factory.CreateHttpsClient();

        var anonymousCsrfToken =
            await GetCsrfTokenAsync(client);

        using var loginResponse = await PostLoginAsync(
            client,
            anonymousCsrfToken,
            DemoUserSeeder.Email,
            DemoUserSeeder.Password);

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var authenticatedCsrfToken =
            await GetCsrfTokenAsync(client);

        using var logoutRequest =
            new HttpRequestMessage(
                HttpMethod.Post,
                "/api/auth/logout");

        logoutRequest.Headers.Add(
            SecurityConstants.AntiforgeryHeaderName,
            authenticatedCsrfToken);

        using var logoutResponse =
            await client.SendAsync(logoutRequest);

        Assert.Equal(
            HttpStatusCode.NoContent,
            logoutResponse.StatusCode);

        var expiredCookie = GetCookie(
            logoutResponse,
            SecurityConstants.AuthenticationCookieName);

        Assert.Contains(
            "expires=",
            expiredCookie.ToLowerInvariant());

        using var sessionResponse =
            await client.GetAsync("/api/auth/session");

        var session =
            await sessionResponse.Content
                .ReadFromJsonAsync<AuthSessionResponse>();

        Assert.NotNull(session);
        Assert.False(session.Authenticated);
        Assert.Null(session.User);
    }

    [Fact]
    public async Task Logout_without_csrf_token_returns_bad_request_for_authenticated_user()
    {
        await using var factory = new ApiWebApplicationFactory();
        await factory.SeedDemoUserAsync();

        using var client = factory.CreateHttpsClient();

        var csrfToken = await GetCsrfTokenAsync(client);

        using var loginResponse = await PostLoginAsync(
            client,
            csrfToken,
            DemoUserSeeder.Email,
            DemoUserSeeder.Password);

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        using var logoutResponse =
            await client.PostAsync("/api/auth/logout", content: null);

        Assert.Equal(
            HttpStatusCode.BadRequest,
            logoutResponse.StatusCode);
    }

    [Fact]
    public async Task Http_login_works_in_development_with_non_secure_cookies()
    {
        await using var factory = new ApiWebApplicationFactory();
        await factory.SeedDemoUserAsync();

        using var client = factory.CreateHttpClient();

        using var csrfResponse =
            await client.GetAsync("/api/auth/csrf");

        Assert.Equal(
            HttpStatusCode.OK,
            csrfResponse.StatusCode);

        var csrfPayload =
            await csrfResponse.Content
                .ReadFromJsonAsync<CsrfTokenResponse>();

        Assert.NotNull(csrfPayload);
        Assert.False(
            string.IsNullOrWhiteSpace(csrfPayload.Token));

        var antiforgeryCookie = GetCookie(
            csrfResponse,
            SecurityConstants.AntiforgeryCookieName);

        var normalizedAntiforgeryCookie =
            antiforgeryCookie.ToLowerInvariant();

        Assert.Contains(
            "httponly",
            normalizedAntiforgeryCookie);

        Assert.Contains(
            "samesite=lax",
            normalizedAntiforgeryCookie);

        Assert.DoesNotContain(
            "; secure",
            normalizedAntiforgeryCookie);

        using var loginResponse = await PostLoginAsync(
            client,
            csrfPayload.Token,
            DemoUserSeeder.Email,
            DemoUserSeeder.Password);

        Assert.Equal(
            HttpStatusCode.OK,
            loginResponse.StatusCode);

        var authenticationCookie = GetCookie(
            loginResponse,
            SecurityConstants.AuthenticationCookieName);

        var normalizedAuthenticationCookie =
            authenticationCookie.ToLowerInvariant();

        Assert.Contains(
            "httponly",
            normalizedAuthenticationCookie);

        Assert.Contains(
            "samesite=lax",
            normalizedAuthenticationCookie);

        Assert.DoesNotContain(
            "; secure",
            normalizedAuthenticationCookie);

        using var sessionResponse =
            await client.GetAsync("/api/auth/session");

        Assert.Equal(
            HttpStatusCode.OK,
            sessionResponse.StatusCode);

        var session =
            await sessionResponse.Content
                .ReadFromJsonAsync<AuthSessionResponse>();

        Assert.NotNull(session);
        Assert.True(session.Authenticated);
        Assert.NotNull(session.User);
        Assert.Equal(
            DemoUserSeeder.Email,
            session.User.Email);
    }

    private static async Task<string> GetCsrfTokenAsync(
        HttpClient client)
    {
        using var response =
            await client.GetAsync("/api/auth/csrf");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        var payload =
            await response.Content
                .ReadFromJsonAsync<CsrfTokenResponse>();

        Assert.NotNull(payload);
        Assert.False(string.IsNullOrWhiteSpace(payload.Token));

        return payload.Token;
    }

    private static Task<HttpResponseMessage> PostLoginAsync(
        HttpClient client,
        string? csrfToken,
        string email,
        string password)
    {
        var request =
            new HttpRequestMessage(
                HttpMethod.Post,
                "/api/auth/login")
            {
                Content = JsonContent.Create(
                    new LoginRequest
                    {
                        Email = email,
                        Password = password
                    })
            };

        if (csrfToken is not null)
        {
            request.Headers.Add(
                SecurityConstants.AntiforgeryHeaderName,
                csrfToken);
        }

        return client.SendAsync(request);
    }

    private static string GetCookie(
        HttpResponseMessage response,
        string cookieName)
    {
        var cookies = response.Headers
            .GetValues("Set-Cookie")
            .Where(value =>
                value.StartsWith(
                    $"{cookieName}=",
                    StringComparison.Ordinal))
            .ToArray();

        Assert.Single(cookies);

        return cookies[0];
    }
}
