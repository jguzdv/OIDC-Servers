using JGUZDV.OIDC.ProtocolServer;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);
builder.ConfigureServices();

var app = builder.Build();
app.Configure();
app.Run();



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
                builder.Configuration.GetSection("Authentication:ADFS").Bind(options);
            })
            .AddCookie(options =>
            {
                options.LoginPath = "/login";
                options.LogoutPath = "/logout";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                options.SlidingExpiration = false;
            });

        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                       .UseDbContext<ApplicationDbContext>();
            })
            //.AddClient(options =>
            //{
            //    options.AllowAuthorizationCodeFlow();

            //    options.UseWebProviders()
            //        .UseActiveDirectoryFederationServices(adfs =>
            //        {
            //            adfs.Configure(adfsOptions =>
            //            {
            //                builder.Configuration.GetSection("Authentication:ADFS").Bind(adfsOptions);
            //            });
            //        });

            //    if (builder.Environment.IsDevelopment())
            //    {
            //        options.AddDevelopmentEncryptionCertificate()
            //            .AddDevelopmentSigningCertificate();
            //    }

            //    options.UseAspNetCore()
            //        .EnableStatusCodePagesIntegration()
            //        .EnableRedirectionEndpointPassthrough()
            //        .EnablePostLogoutRedirectionEndpointPassthrough();
            //})
            //.AddServer(options =>
            //{
            //    // Enable the authorization, device, introspection,
            //    // logout, token, userinfo and verification endpoints.
            //    options.SetAuthorizationEndpointUris("connect/authorize")
            //           .SetDeviceEndpointUris("connect/device")
            //           .SetIntrospectionEndpointUris("connect/introspect")
            //           .SetLogoutEndpointUris("connect/logout")
            //           .SetTokenEndpointUris("connect/token")
            //           .SetUserinfoEndpointUris("connect/userinfo")
            //           .SetVerificationEndpointUris("connect/verify");

            //    // Note: this sample uses the code, device code, password and refresh token flows, but you
            //    // can enable the other flows if you need to support implicit or client credentials.
            //    options.AllowAuthorizationCodeFlow()
            //           .AllowDeviceCodeFlow()
            //           .AllowPasswordFlow()
            //           .AllowRefreshTokenFlow();

            //    if (builder.Environment.IsDevelopment()) {
            //        options.AddDevelopmentEncryptionCertificate()
            //               .AddDevelopmentSigningCertificate();
            //    } 
            //    else
            //    {
            //        //TODO: Load keys protected keys from storage - see through auto-rollover
            //    }

            //    options.UseDataProtection();

            //    // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
            //    options.UseAspNetCore()
            //           .EnableStatusCodePagesIntegration()
            //           .EnableAuthorizationEndpointPassthrough()
            //           .EnableLogoutEndpointPassthrough()
            //           .EnableTokenEndpointPassthrough()
            //           .EnableUserinfoEndpointPassthrough()
            //           .EnableVerificationEndpointPassthrough();
            //})

            // Register the OpenIddict validation components.
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseDataProtection();
                options.UseAspNetCore();
            });
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
}