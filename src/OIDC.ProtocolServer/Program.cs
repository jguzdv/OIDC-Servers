using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

using JGUZDV.ActiveDirectory.ClaimProvider.Configuration;
using JGUZDV.ActiveDirectory.ClaimProvider.PropertyConverters;
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
        services.AddControllersWithViews();
        services.AddRazorPages(pages =>
        {
            pages.RootDirectory = "/Web/Pages";
        });

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            var connectionString = builder.Configuration.GetConnectionString(nameof(ApplicationDbContext));
            options.UseSqlServer(connectionString);
            options.UseOpenIddict();
        });

        services.AddAuthentication(options => {
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
            });

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
                options.SetAuthorizationEndpointUris("connect/authorize")
                       .SetDeviceEndpointUris("connect/device")
                       .SetIntrospectionEndpointUris("connect/introspect")
                       .SetTokenEndpointUris("connect/token")
                       .SetUserinfoEndpointUris("connect/userinfo")
                       .SetVerificationEndpointUris("connect/verify")
                       .SetLogoutEndpointUris("connect/logout");


                options.AllowAuthorizationCodeFlow()
                       .AllowDeviceCodeFlow()
                       .AllowRefreshTokenFlow();


                if (builder.Environment.IsDevelopment())
                {
                    options.AddDevelopmentEncryptionCertificate()
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
            .AddClaimProvider<ActiveDirectoryClaimProviderFacade>();
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
        app.MapRazorPages();
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
            RedirectUris = { new Uri("https://localhost:6001") },
            Permissions =
            {
                Permissions.Prefixes.Scope + "sample",
                Permissions.Endpoints.Authorization,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.ResponseTypes.Code,
            },
            ConsentType = ConsentTypes.Implicit,
            Properties=
            {
                { "claimTypes", JsonSerializer.SerializeToElement(new[] { "some_claim" }) },
                { "staticClaims", JsonSerializer.SerializeToElement(new[] { new { Type="claimType", Value="claimValue" } }) }
            }
        });

        var sampleScope = await scopeManager.FindByNameAsync("sample");
        if (sampleScope != null)
        {
            await scopeManager.DeleteAsync(sampleScope);
        }

        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = "sample",
            Properties =
            {
                { "claimTypes", JsonSerializer.SerializeToElement(new[] { "some_claim" }) }
            }
        });
    }
#endif
}