using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

using JGUZDV.ActiveDirectory.ClaimProvider.Configuration;
using JGUZDV.OIDC.ProtocolServer;
using JGUZDV.OIDC.ProtocolServer.ClaimProviders;
using JGUZDV.OIDC.ProtocolServer.Configuration;
using JGUZDV.OIDC.ProtocolServer.Data;
using JGUZDV.OIDC.ProtocolServer.OpenIddictExt;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;

using OpenIddict.Abstractions;

using static OpenIddict.Abstractions.OpenIddictConstants;

IdentityModelEventSource.ShowPII = true;
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;
services.AddTransient(sp => TimeProvider.System);
services.AddSingleton(sp => (IConfigurationRoot)sp.GetRequiredService<IConfiguration>());

services.AddControllersWithViews()
    .AddRazorOptions(opt =>
    {
        opt.ViewLocationFormats.Clear();
        opt.ViewLocationFormats.Add("/Web/Views/{1}/{0}.cshtml");
        opt.ViewLocationFormats.Add("/Web/Views/Shared/{0}.cshtml");
    });

services.AddDbContext<ApplicationDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString(nameof(ApplicationDbContext));
    options.UseSqlServer(connectionString);
    options.UseOpenIddict();
});

if (builder.Environment.IsDevelopment())
{
    services.AddDistributedMemoryCache();
}
else
{
    // TODO: Add DistributedCache here.
    throw new NotImplementedException();
}

services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
    .AddOpenIdConnect(options =>
    {
                builder.Configuration
                    .GetSection("Authentication:OpenIdConnect")
                    .Bind(options);
    })
    .AddCookie(options =>
    {
        options.LoginPath = "/authn/login";
        options.LogoutPath = "/authn/logout";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
        options.SlidingExpiration = false;
    })
    .AddCookieDistributedTicketStore();

services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
                .UseDbContext<ApplicationDbContext>();

        options.ReplaceApplicationManager<JGUApplicationManager>();
    })
    .AddServer(options =>
    {
        // Enable the authorization, device, introspection,
        // logout, token, userinfo and verification endpoints.
        options
            .SetAuthorizationEndpointUris("connect/authorize")
            .SetDeviceEndpointUris("connect/device")
            .SetIntrospectionEndpointUris("connect/introspect")
            .SetTokenEndpointUris("connect/token")
            .SetUserinfoEndpointUris("connect/userinfo")
            .SetVerificationEndpointUris("connect/verify")
            .SetLogoutEndpointUris("connect/logout");

        options
            .AllowAuthorizationCodeFlow()
            .AllowDeviceCodeFlow()
            .AllowRefreshTokenFlow();


        //if (builder.Environment.IsDevelopment())
        //{
        //    options
        //        .AddDevelopmentEncryptionCertificate()
        //        .AddDevelopmentSigningCertificate();
        //}

        options.UseDataProtection()
            .PreferDefaultAccessTokenFormat();

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

services.AddAutomaticKeyRollover(conf =>
{
    conf.KeyStorePath = "D:\\Temp\\OIDC-KeyStorePath";
    conf.DisableKeyGeneration = false;
});

services
    .AddOptions<ProtocolServerOptions>()
    .BindConfiguration("ProtocolServer")
    .ValidateDataAnnotations()
    .ValidateOnStart();

services.AddOptions<ActiveDirectoryOptions>()
    .BindConfiguration("ActiveDirectory")
    .PostConfigure<IOptions<ProtocolServerOptions>>((adOptions, serverOptions) =>
    {
        adOptions.UserClaimType = serverOptions.Value.UserClaimType;

        foreach (var conv in serverOptions.Value.Properties)
            adOptions.Properties.Add(new ADPropertyInfo(conv.Key, conv.Value switch
            {
                "int" => typeof(int),
                "long" => typeof(long),
                "DateTime" => typeof(DateTime),
                "byte[]" => typeof(byte[]),
                _ => typeof(string)
            }));

        foreach (var src in serverOptions.Value.ClaimSources)
        {
            adOptions.ClaimSources.RemoveAll(c => c.ClaimType.Equals(src.ClaimType, StringComparison.OrdinalIgnoreCase));
            adOptions.ClaimSources.Add(src);
        }
    })
    .ValidateDataAnnotations()
    .ValidateOnStart();

services
    .AddActiveDirectoryClaimProvider()
    .AddClaimProvider<ActiveDirectoryClaimProviderFacade>()
    .AddScoped<UserValidationProvider>();


var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}
else
{
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();



#if DEBUG
app.MapGet("/test", async (IOptionsSnapshot<OpenIdConnectOptions> opt, CancellationToken ct) =>
{
    var options = opt.Get(OpenIdConnectDefaults.AuthenticationScheme);
    var config = await options.ConfigurationManager.GetConfigurationAsync(ct);

    return JsonSerializer.Serialize(config);
});

await Startup.InitializeSamples(app);
#endif

app.Run();



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
            Permissions =
            {
                Permissions.Scopes.Profile,
                Permissions.Prefixes.Scope + "sample",
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.ResponseTypes.Code,
            },
            ConsentType = ConsentTypes.Implicit,
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
                        RequestedClaimTypes = ["umz_uuid"]
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
                        RequestedClaimTypes = ["email", "birthdate", "name", "family_name", "given_name", "gender", "locale", "preferred_username", "picture", "updated_at", "website", "zoneinfo"]
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