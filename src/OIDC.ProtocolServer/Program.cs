using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

using JGUZDV.ActiveDirectory;
using JGUZDV.ActiveDirectory.Configuration;
using JGUZDV.OIDC.ProtocolServer.ActiveDirectory;
using JGUZDV.OIDC.ProtocolServer.Authentication;
using JGUZDV.OIDC.ProtocolServer.ClaimProviders;
using JGUZDV.OIDC.ProtocolServer.Configuration;
using JGUZDV.OIDC.ProtocolServer.Model;
using JGUZDV.OIDC.ProtocolServer.OpenIddictExt;
using JGUZDV.OpenIddict.KeyManager.Configuration;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;

using OpenIddict.Abstractions;

using Constants = JGUZDV.OIDC.ProtocolServer.Constants;
using OpenIddictConstants = OpenIddict.Abstractions.OpenIddictConstants;

IdentityModelEventSource.ShowPII = true;
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

var builder = WebApplication.CreateBuilder(args);
builder.UseJGUZDVLogging();

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
    services.AddDataProtection();
    services.AddDistributedMemoryCache();
}
else
{
    builder.AddJGUZDVDataProtection();
    services.AddDistributedSqlServerCache(opt => builder.Configuration.GetSection("DistributedCache").Bind(opt));
}

services.AddSingleton<CustomOpenIdConnectEvents>();
services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
    .AddOpenIdConnect(
        Constants.AuthenticationSchemes.OIDC,
        options =>
        {
            builder.Configuration
                .GetSection("Authentication:OpenIdConnect")
                .Bind(options);

            options.EventsType = typeof(CustomOpenIdConnectEvents);
        }
    )
    .AddOpenIdConnect(
        Constants.AuthenticationSchemes.MFA,
        options =>
        {
            builder.Configuration
                .GetSection("Authentication:OpenIdConnect-MFA")
                .Bind(options);

            options.CallbackPath = "/signin-oidc-mfa";
            options.EventsType = typeof(CustomOpenIdConnectEvents);
        }
    )
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
        if(builder.Configuration.GetValue<string>("ProtocolServer:Issuer") is string issuer and { Length: > 0 })
        {
            options.SetIssuer(issuer);
        }

        // Enable the authorization, device, introspection,
        // logout, token, userinfo and verification endpoints.
        options
            .SetAuthorizationEndpointUris("connect/authorize")
            .SetDeviceEndpointUris("connect/device")
            .SetIntrospectionEndpointUris("connect/introspect")
            .SetTokenEndpointUris("connect/token")
            .SetUserinfoEndpointUris("connect/userinfo")
            .SetVerificationEndpointUris("connect/verify")
            .SetLogoutEndpointUris("connect/endsession");

        options
            .AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow()
            .AllowClientCredentialsFlow()
            .AllowImplicitFlow()
            .AllowHybridFlow();


        //if (builder.Environment.IsDevelopment())
        //{
        //    options
        //        .AddDevelopmentEncryptionCertificate()
        //        .AddDevelopmentSigningCertificate();
        //}

        options.UseDataProtection()
            .PreferDefaultAccessTokenFormat();

        // TODO: Consider reenabling this.
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

services.AddAutomaticKeyRollover(
    OpenIddictKeyManagerExtensions.KeyType.X509,
    conf =>
    {
        conf.KeyStorePath = builder.Configuration["KeyStoreagePath"];
        conf.DisableKeyGeneration = false;
    });

services.Configure<X509Options>(conf =>
{
    conf.CertificatePassword = builder.Configuration["CertificatePassword"];
});

services
    .AddOptions<ProtocolServerOptions>()
    .BindConfiguration("ProtocolServer")
    .ValidateDataAnnotations()
    .ValidateOnStart();

services.AddSingleton<DirectoryEntryProvider>();
services.AddPropertyReader();
services.AddClaimProvider();

services.AddOptions<PropertyReaderOptions>()
    .PostConfigure<IOptions<ProtocolServerOptions>>((readerOptions, serverOptions) =>
    {
        foreach (var prop in serverOptions.Value.Properties)
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

services.AddOptions<ClaimProviderOptions>()
    .PostConfigure<IOptions<ProtocolServerOptions>>((cpOptions, serverOptions) =>
    {
        foreach (var src in serverOptions.Value.ClaimSources)
        {
            cpOptions.ClaimSources.RemoveAll(c => c.ClaimType.Equals(src.ClaimType, StringComparison.OrdinalIgnoreCase));
            cpOptions.ClaimSources.Add(src);
        }
    });

services
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
app.MapGet("/test", async (IOptions<DataProtectionOptions> opt) =>
{
    var thing = opt.Value.ApplicationDiscriminator;
    //var thing = discriminator.Discriminator;

    return JsonSerializer.Serialize(thing);
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