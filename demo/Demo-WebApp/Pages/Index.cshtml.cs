using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Demo_WebApp.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly IOptionsMonitor<OpenIdConnectOptions> _optionsMonitor;

        public IndexModel(ILogger<IndexModel> logger, IOptionsMonitor<OpenIdConnectOptions> optionsMonitor)
        {
            _logger = logger;
            _optionsMonitor = optionsMonitor;
        }

        public AuthenticateResult? AuthResult { get; set; }

        public async Task OnGet()
        {
            AuthResult = await HttpContext.AuthenticateAsync();
        }

        public async void OnPost()
        {
            AuthResult = await HttpContext.AuthenticateAsync();

            var options = _optionsMonitor.Get(OpenIdConnectDefaults.AuthenticationScheme);
            var config = await options.ConfigurationManager!.GetConfigurationAsync(HttpContext.RequestAborted);

            var refreshToken = AuthResult.Properties.GetTokenValue("refresh_token");
            // Use the refresh token to get a new access token
            var response = await options.Backchannel.SendAsync(new(HttpMethod.Post, config.TokenEndpoint)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["refresh_token"] = refreshToken,
                    ["client_id"] = options.ClientId,
                    ["client_secret"] = options.ClientSecret
                })
            });

            var payload = await response.Content.ReadAsStringAsync();
        }
    }
}