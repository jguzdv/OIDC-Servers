using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

using JGUZDV.ActiveDirectory.ClaimProvider.Configuration;
using JGUZDV.OIDC.ProtocolServer;
using JGUZDV.OIDC.ProtocolServer.ClaimProviders;
using JGUZDV.OIDC.ProtocolServer.Configuration;
using JGUZDV.OIDC.ProtocolServer.Data;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

using OpenIddict.Abstractions;

using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
builder.ConfigureServices();

var app = builder.Build();
app.Configure();

#if DEBUG
await Startup.InitializeSamples(app);
#endif

await app.RunAsync();



internal static class Startup
{
    static Startup()
    {
        JwtSecurityTokenHandler.DefaultMapInboundClaims = false;
    }

    public static void ConfigureServices(this WebApplicationBuilder builder)
    {
        var services = builder.Services;
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
                builder.Configuration.GetSection("Authentication:OIDC").Bind(options);
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


                if (builder.Environment.IsDevelopment())
                {
                    options
                        .DisableAccessTokenEncryption()
                        .AddDevelopmentEncryptionCertificate()
                        .AddDevelopmentSigningCertificate();
                }
                else
                {
                    //TODO: Load keys protected keys from storage - see through auto-rollover
                }


                options.UseDataProtection();

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
    }

    public static void Configure(this WebApplication app)
    {
        // Configure the HTTP request pipeline.
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
        app.MapDefaultControllerRoute();
    }

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
                { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "some_claim" }) },
                { Constants.Properties.StaticClaims, JsonSerializer.SerializeToElement(new[] { new { Type="static_1", Value="uhh value!" } }) }
            }
        });

        foreach (var s in new[] { "openid","uuid","accountname","roles","groups","name","email","phone","profile","matriculation_number","home_dir","affiliation" })
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
            Properties = { { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "sub", "zdv_sid", "zdv_upn", "upn", "security_identifier", "uid" }) } }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "uuid",
            Properties = { { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "umz_uuid" }) }
        }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "accountname",
            Properties = { { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "zdv_accountName" }) } }
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "roles",
            Properties = { { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "role" }) }
}
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "groups",
            Properties = { { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "role" }) }
}
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "name",
            Properties = { { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "name", "family_name", "given_name" }) }
}
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "email",
            Properties = { { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "email" }) }
}
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "phone",
            Properties = { { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "phone_number" }) }
}
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "profile",
            Properties = { { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "email", "birthdate", "name", "family_name", "given_name", "gender", "locale", "preferred_username", "picture", "updated_at", "website", "zoneinfo" }) }
}
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "matriculation_number",
            Properties = { { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "matriculation_number" }) }
}
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "home_dir",
            Properties = { { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "home_directory" }) }
}
        });
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "affiliation",
            Properties = { { Constants.Properties.ClaimTypes, JsonSerializer.SerializeToElement(new[] { "scoped_affiliation" }) } }
        });
    }
#endif
}