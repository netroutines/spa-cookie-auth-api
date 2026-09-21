# SpaCookieAuth.Api

A self-contained ASP.NET Core 10 reference API for cookie-based authentication in first-party SPAs, using ASP.NET Core
Identity, antiforgery protection, CORS, and EF Core InMemory.

<p>
  <a href="https://github.com/netroutines/spa-cookie-auth-api/actions/workflows/tests.yaml">
    <img src="https://github.com/netroutines/spa-cookie-auth-api/actions/workflows/tests.yaml/badge.svg?branch=main&event=push" alt="Build Status">
  </a>
</p>

## Overview

This repository demonstrates a cookie-based authentication flow for first-party single-page applications built with
frameworks such as React, Vue, or Angular.

The API uses:

- ASP.NET Core Identity for user and password management
- an HttpOnly authentication cookie
- ASP.NET Core antiforgery protection for state-changing requests
- credentialed CORS for a separately hosted first-party SPA
- EF Core InMemory to keep the sample self-contained
- integration tests for authentication, CSRF, cookies, lockout behavior, logout, caching, and CORS

EF Core InMemory is used intentionally to keep the sample self-contained. It is not intended as a production persistence
provider.

## Requirements

- .NET SDK 10.0.401, or a compatible SDK allowed by `global.json`
- a trusted ASP.NET Core development HTTPS certificate for local HTTPS development

Trust the local development certificate if needed:

```powershell
dotnet dev-certs https --trust
```

## Run the API

From the repository root:

```powershell
dotnet restore

dotnet run `
    --project .\src\SpaCookieAuth.Api `
    -- `
    --seed-demo-user
```

The development server listens on:

```text
https://localhost:7227
http://localhost:5064
```

The optional `--seed-demo-user` argument creates the following in-memory demo account:

```text
Email:    user@demo.test
Password: DemoPassword1!
```

Because EF Core InMemory is used, the database and demo user exist only for the lifetime of the application process.

To start the API without creating the demo user:

```powershell
dotnet run --project .\src\SpaCookieAuth.Api
```

## Authentication flow

The API exposes four authentication endpoints:

| Method | Endpoint            | Purpose                                       |
|--------|---------------------|-----------------------------------------------|
| `GET`  | `/api/auth/csrf`    | Gets an antiforgery token                     |
| `POST` | `/api/auth/login`   | Signs in and issues the authentication cookie |
| `GET`  | `/api/auth/session` | Returns the current authentication state      |
| `POST` | `/api/auth/logout`  | Signs out the authenticated user              |

State-changing requests require the antiforgery token in the `X-XSRF-TOKEN` header.

Browser-based SPAs should send requests with credentials enabled so the authentication and antiforgery cookies are
included.

## Notes

The development CORS configuration allows `https://localhost:5173` by default. Add or replace origins in
`src/SpaCookieAuth.Api/appsettings.Development.json` to match your SPA development server.

For production use, replace EF Core InMemory with a persistent database and review Data Protection key persistence,
HTTPS/reverse-proxy configuration, secrets management, and production CORS origins.
