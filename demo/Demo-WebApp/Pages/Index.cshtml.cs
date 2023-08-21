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

            var result = auth.Properties?.Items
                .Select(x => $"{x.Key} => {x.Value}\r\n")
                .Aggregate("", (x, c) => x + c);


            result += auth.Principal?.Claims
                .Select(x => $"{x.Type}: {x.Value}\r\n")
                .Aggregate("", (x, c) => x + c);

            Result = result;
        }
    }
}