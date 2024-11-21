using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;

using JGUZDV.ActiveDirectory;
using JGUZDV.ActiveDirectory.Configuration;
using JGUZDV.OIDC.ProtocolServer.ActiveDirectory;
using JGUZDV.OIDC.ProtocolServer.ClaimProviders;
using JGUZDV.OIDC.ProtocolServer.Configuration;
using JGUZDV.OIDC.ProtocolServer.Model;
using JGUZDV.OIDC.ProtocolServer.OpenIddictExt;
using JGUZDV.OIDC.ProtocolServer.Web;
using JGUZDV.OpenIddict.KeyManager.Configuration;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;

using OIDC.ProtocolServer.OpenTelemetry;

using OpenIddict.Abstractions;

using OpenTelemetry.Logs;

using Constants = JGUZDV.OIDC.ProtocolServer.Constants;
using OpenIddictConstants = OpenIddict.Abstractions.OpenIddictConstants;

IdentityModelEventSource.ShowPII = true;
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

// Basic setup & logging
var builder = WebApplication.CreateBuilder(args);
//builder.UseJGUZDVLogging();
var services = builder.Services;

// Default OpenTelemetry config, needs the OpenTelemetry config section.
builder.AddJGUZDVOpenTelemetry();
services.AddSingleton<MeterContainer>();

//builder.Logging.AddFilter<OpenTelemetryLoggerProvider>("*", LogLevel.Information);

services.AddTransient(sp => TimeProvider.System);
services.AddSingleton(sp => (IConfigurationRoot)sp.GetRequiredService<IConfiguration>());

// Some functions will need MVC, so we add it.
// To have some folder structures, we set the view location formats.
services.AddControllersWithViews()
    .AddRazorOptions(opt =>
    {
        opt.ViewLocationFormats.Clear();
        opt.ViewLocationFormats.Add("/Web/Views/{1}/{0}.cshtml");
        opt.ViewLocationFormats.Add("/Web/Views/Shared/{0}.cshtml");
    });

// Add the database context and register OpenIddict.
services.AddDbContext<ApplicationDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString(nameof(ApplicationDbContext));
    options.UseSqlServer(connectionString);
    options.UseOpenIddict();
});


if (builder.Environment.IsDevelopment())
{
    services.AddDataProtection();
    services.AddDistributedMemoryCache();
}
else
{
    // Data protection and distributed cache are required, since else cookies will explode in size.
    builder.AddJGUZDVDataProtection();
    services.AddDistributedSqlServerCache(opt => builder.Configuration.GetSection("DistributedCache").Bind(opt));
}


services.AddAuthentication(options =>
{
    // Local login will be done via cookies and OIDC from another host.
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
    // Add OIDC for non MFA'd logins.
    .AddOpenIdConnect(
        Constants.AuthenticationSchemes.OIDC,
        options =>
        {
            builder.Configuration
                .GetSection("Authentication:OpenIdConnect")
                .Bind(options);

            // We want to be able to map all incomming claims, since we read them in PrincipalClaimProvider.
            options.ClaimActions.MapAll();

            // This allows us to distinguish between the remote OIDC login at the provider and the local login.
            options.TokenValidationParameters.AuthenticationType = Constants.AuthenticationTypes.RemoteOIDC;
        }
    )

    // Add OIDC for MFA'd logins.
    .AddOpenIdConnect(
        Constants.AuthenticationSchemes.MFA,
        options =>
        {
            builder.Configuration
                .GetSection("Authentication:OpenIdConnect-MFA")
                .Bind(options);

            options.CallbackPath = "/signin-oidc-mfa";

            // We want to be able to map all incomming claims, since we read them in PrincipalClaimProvider.
            options.ClaimActions.MapAll();

            // This allows us to distinguish between the remote OIDC login at the provider and the local login.
            options.TokenValidationParameters.AuthenticationType = Constants.AuthenticationTypes.RemoteOIDC;
        }
    )
    // We'll use a short lived cookie for the login, since the OIDC server configured above has own lifetimes for cookies.
    .AddCookie(options =>
    {
        options.LoginPath = "/authn/login";
        options.LogoutPath = "/authn/logout";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
        options.SlidingExpiration = false;
    })
    .AddCookieDistributedTicketStore();

services.AddTransient<IPostConfigureOptions<OpenIdConnectOptions>, PostConfigureOIDCOptions>();


services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<ApplicationDbContext>();

        // Our own application manager, that will handle some left overs stuff from migrating from IdentityServer4.
        options.ReplaceApplicationManager<JGUApplicationManager>();
    })
    .AddServer(options =>
    {
        // If the config contains an issuer, we'll use it.
        if (builder.Configuration.GetValue<string>("ProtocolServer:Issuer") is string issuer and { Length: > 0 })
        {
            options.SetIssuer(issuer);
        }

        // Enable the authorization, device, introspection,
        // logout, token, userinfo and verification endpoints.
        options
            .SetAuthorizationEndpointUris("connect/authorize")
            //.SetDeviceEndpointUris("connect/device")
            //.SetIntrospectionEndpointUris("connect/introspect")
            .SetTokenEndpointUris("connect/token")
            .SetUserinfoEndpointUris("connect/userinfo")
            //.SetVerificationEndpointUris("connect/verify")
            .SetLogoutEndpointUris("connect/endsession");

        options
            .AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow()
            .AllowClientCredentialsFlow()
            .AllowImplicitFlow()
            .AllowHybridFlow();

        // Remove a check, if the scope parameter exists on request to the token endpoint.
        options.RemoveEventHandler(OpenIddict.Server.OpenIddictServerHandlers.Exchange.ValidateScopeParameter.Descriptor);

        // We'll use a rather long default lifetime for AccessTokens:
        options.SetAccessTokenLifetime(TimeSpan.FromHours(8));
        options.SetIdentityTokenLifetime(TimeSpan.FromHours(8));

        //if (builder.Environment.IsDevelopment())
        //{
        //    options
        //        .AddDevelopmentEncryptionCertificate()
        //        .AddDevelopmentSigningCertificate();
        //}

        options.UseDataProtection()
            .PreferDefaultAccessTokenFormat();

        // TODO: Consider reenabling this.
        // Disable the automatic encryption of access tokens - we're not sure all our software can handle it.
        options.Configure(opt => opt.DisableAccessTokenEncryption = true);

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options.UseAspNetCore()
            .EnableStatusCodePagesIntegration()
            .EnableAuthorizationEndpointPassthrough()
            .EnableLogoutEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserinfoEndpointPassthrough()
            .EnableVerificationEndpointPassthrough();
    })
    // Register the OpenIddict validation components.
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseDataProtection();
        options.UseAspNetCore();
    });

// Automatic key rollover will provide new certificates, if the old ones are about to expire.
services.AddAutomaticKeyRollover(
    OpenIddictKeyManagerExtensions.KeyType.X509,
    conf =>
    {
        conf.KeyStorePath = builder.Configuration["ProtocolServer:JWKS:KeyStoragePath"];
        conf.DisableKeyGeneration = false;
    });

services.Configure<X509Options>(conf =>
{
    conf.CertificatePassword = builder.Configuration["ProtocolServer:JWKS:CertificatePassword"];
});

services
    .AddOptions<ProtocolServerOptions>()
    .BindConfiguration("ProtocolServer")
    .ValidateDataAnnotations()
    .ValidateOnStart();

services.AddScoped<OIDCContextProvider>();
services.AddScoped<IdentityProvider>();

services.AddSingleton<DirectoryEntryProvider>();
services.AddPropertyReader();
services.AddClaimProvider();

// Add property reader options for the properties we want to read from the AD.
services.AddOptions<PropertyReaderOptions>()
    .PostConfigure<IOptions<ProtocolServerOptions>>((readerOptions, serverOptions) =>
    {
        foreach (var prop in serverOptions.Value.ActiveDirectory.Properties)
        {
            readerOptions.PropertyInfos.Add(
                prop.Key,
                new(
                    prop.Key,
                    prop.Value switch
                    {
                        "int" => typeof(int),
                        "long" => typeof(long),
                        "DateTime" => typeof(DateTime),
                        "byte[]" => typeof(byte[]),
                        _ => typeof(string)
                    }
                )
            );
        }
    });

// Same, but for claims.
services.AddOptions<ClaimProviderOptions>()
    .PostConfigure<IOptions<ProtocolServerOptions>>((cpOptions, serverOptions) =>
    {
        foreach (var src in serverOptions.Value.ActiveDirectory.ClaimSources)
        {
            cpOptions.ClaimSources.RemoveAll(c => c.ClaimType.Equals(src.ClaimType, StringComparison.OrdinalIgnoreCase));
            cpOptions.ClaimSources.Add(src);
        }
    });


services
    .AddClaimProvider<ActiveDirectoryClaimProviderFacade>()
    .AddClaimProvider<JGUDirectoryClaimProvider>()
    .AddClaimProvider<PrincipalClaimProvider>()
    .AddScoped<UserValidationProvider>();


// Finished setting up the services, now build the app.

var app = builder.Build();

if (app.Environment.IsProduction())
{
    app.UseExceptionHandler("/Error");
}
else
{
    app.UseDeveloperExceptionPage();
}

// This middleware filters AuthenticationFailureExceptions with "correlation failed"
app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (AuthenticationFailureException ex)
        when (ex.InnerException?.Message.Contains("Correlation", StringComparison.OrdinalIgnoreCase) == true)
    {
        context.Response.Redirect("/Error/Correlation");
        return;
    }
});

if (app.Environment.IsProduction())
{
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();


// This is mainly the HomeController, that will render some views.
app.MapControllers();

// Endpoints triggering login and logout
var authn = app.MapGroup("/authn");
authn.MapGet("/login", Endpoints.Authentication.Challenge);
authn.MapGet("/logout", Endpoints.Authentication.SignOut);


// OIDC Endpoints
var connect = app.MapGroup("/connect");
connect.MapMethods("/authorize", [HttpMethods.Get, HttpMethods.Post], Endpoints.OIDC.Authorize)
    .DisableAntiforgery()
    .Produces(200, contentType: "application/json");

connect.MapPost("/token", Endpoints.OIDC.Exchange)
    .DisableAntiforgery();

connect.MapMethods("/userinfo", [HttpMethods.Get, HttpMethods.Post], Endpoints.OIDC.UserInfo)
    .DisableAntiforgery()
    .Produces(200, contentType: "application/json");

//connect.MapPost("/endsession", Endpoints.OIDC.EndSession);

app.Run();


// Code for debugging things
internal static class Startup
{

#if DEBUG
    internal static async Task InitializeSamples(WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

        var sampleClient = await applicationManager.FindByClientIdAsync("sample");
        if (sampleClient != null)
        {
            await applicationManager.DeleteAsync(sampleClient);
        }

        await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "sample",
            ClientSecret = "P@ssword!1",
            RedirectUris = { new Uri("https://localhost:5001/signin-oidc") },
            PostLogoutRedirectUris = { new Uri("https://localhost:5001/signout-callback-oidc") },
            Permissions =
            {
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Prefixes.Scope + "sample",
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials
            },
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            Properties =
            {
                {
                    CustomProperties.PropertyName,
                    (new ApplicationProperties
                        {
                            RequestedClaimTypes = ["some_claim"],
                            StaticClaims = [new("static_1", "uhh value!")]
                        }
                    ).Serialize()
                }
            }
        });

        sampleClient = await applicationManager.FindByClientIdAsync("sample-mfa");
        if (sampleClient != null)
        {
            await applicationManager.DeleteAsync(sampleClient);
        }

        await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "sample-mfa",
            ClientSecret = "P@ssword!1",
            RedirectUris = { new Uri("https://localhost:5001/signin-oidc") },
            PostLogoutRedirectUris = { new Uri("https://localhost:5001/signout-callback-oidc") },
            Permissions =
            {
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Prefixes.Scope + "sample",
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken
            },
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            Properties =
            {
                {
                    CustomProperties.PropertyName,
                    (new ApplicationProperties
                        {
                            RequestedClaimTypes = ["some_claim"],
                            StaticClaims = [new("static_1", "uhh value!")],
                            MFA = new()
                            {
                                Required = true,
                            }
                        }
                    ).Serialize()
                }
            }
        });

        foreach (var s in new[] { "openid", "uuid", "accountname", "roles", "groups", "name", "email", "phone", "profile", "matriculation_number", "home_dir", "affiliation" })
        {
            var sampleScope = await scopeManager.FindByNameAsync(s);
            if (sampleScope != null)
            {
                await scopeManager.DeleteAsync(sampleScope);
            }
        }

        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "openid",
            Properties =
            {
                {
                CustomProperties.PropertyName,
                (new ScopeProperties
                    {
                        RequestedClaimTypes = ["sub", "zdv_sid", "zdv_upn", "upn", "security_identifier", "uid"]
                    }).Serialize()
                }
            }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "uuid",
            Properties =
            {
                {
                CustomProperties.PropertyName,
                (new ScopeProperties
                    {
                        RequestedClaimTypes = ["zdv_uuid"]
                    }).Serialize()
                }
            }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "accountname",
            Properties =
            {
                {
                CustomProperties.PropertyName,
                (new ScopeProperties
                    {
                        RequestedClaimTypes = ["zdv_accountName"]
                    }).Serialize()
                }
            }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "roles",
            Properties =
            {
                {
                CustomProperties.PropertyName,
                (new ScopeProperties
                    {
                        RequestedClaimTypes = ["role"]
                    }).Serialize()
                }
            }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "groups",
            Properties =
            {
                {
                CustomProperties.PropertyName,
                (new ScopeProperties
                    {
                        RequestedClaimTypes = ["role"]
                    }).Serialize()
                }
            }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "name",
            Properties =
            {
                {
                CustomProperties.PropertyName,
                (new ScopeProperties
                    {
                        RequestedClaimTypes = ["name", "family_name", "given_name"]
                    }).Serialize()
                }
            }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "email",
            Properties =
            {
                {
                CustomProperties.PropertyName,
                (new ScopeProperties
                    {
                        RequestedClaimTypes = ["email"]
                    }).Serialize()
                }
            }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "phone",
            Properties =
            {
                {
                CustomProperties.PropertyName,
                (new ScopeProperties
                    {
                        RequestedClaimTypes = ["phone_number"]
                    }).Serialize()
                }
            }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "profile",
            Properties =
            {
                {
                CustomProperties.PropertyName,
                (new ScopeProperties
                    {
                        RequestedClaimTypes = ["email", "birthdate", "name", "family_name", "given_name", "gender", "locale", "preferred_username", "picture", "updated_at", "website", "zoneinfo"],
                        TargetToken = { "id_token" }
                    }).Serialize()
                }
            }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "matriculation_number",
            Properties =
            {
                {
                CustomProperties.PropertyName,
                (new ScopeProperties
                    {
                        RequestedClaimTypes = ["matriculation_number"]
                    }).Serialize()
                }
            }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "home_dir",
            Properties =
            {
                {
                CustomProperties.PropertyName,
                (new ScopeProperties
                    {
                        RequestedClaimTypes = [ "home_directory" ]
                    }).Serialize()
                }
            }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "affiliation",
            Properties =
            {
                {
                CustomProperties.PropertyName,
                (new ScopeProperties
                    {
                        RequestedClaimTypes = ["scoped_affiliation"]
                    }).Serialize()
                }
            }
        });
    }
#endif
}