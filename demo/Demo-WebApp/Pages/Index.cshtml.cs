using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Demo_WebApp.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        public string Result { get; set; }

        [Authorize]
        public async Task OnGet()
        {
            var auth = await HttpContext.AuthenticateAsync();

            if(auth.Properties?.Items.Any() == true)
                Result += string.Join("\r\n", auth.Properties.Items.Select(x => $"{x.Key} => {x.Value}")) + "\r\n"; ;

            if (auth.Principal?.Claims.Any() == true)
                Result += string.Join("\r\n", auth.Principal.Claims.Select(x => $"{x.Type}: {x.Value}\r\n")) + "\r\n";
        }
    }
}