using JGUZDV.OIDC.ProtocolServer.Model;
using JGUZDV.OIDC.Tools.ConfigUI.Data;

using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace JGUZDV.OIDC.Tools.ConfigUI;

public static class MauiProgram
{
	public static MauiApp CreateMauiApp(string[] args)
	{
        var connectionBuilder = new SqlConnectionStringBuilder
        {
            DataSource = args[1],
            InitialCatalog = args[2],
            IntegratedSecurity = true,
            Encrypt = false
        };

        var builder = MauiApp.CreateBuilder();
		builder
			.UseMauiApp<App>()
			.ConfigureFonts(fonts =>
			{
				fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
			});

		builder.Services.AddMauiBlazorWebView();

#if DEBUG
		builder.Services.AddBlazorWebViewDeveloperTools();
		builder.Logging.AddDebug();
#endif

        builder.Services.AddSingleton<ConfigAppContext>();
        builder.Services.AddDbContext<ApplicationDbContext>(
            ef =>
            {
                ef.UseSqlServer(connectionBuilder.ConnectionString);
                ef.UseOpenIddict();
            }
        );

        builder.Services.AddOpenIddict(oidc =>
        {
            oidc.AddCore(core =>
            {
                core.UseEntityFrameworkCore(c =>
                {
                    c.UseDbContext<ApplicationDbContext>();
                });
            });
        });

		return builder.Build();
	}
}
