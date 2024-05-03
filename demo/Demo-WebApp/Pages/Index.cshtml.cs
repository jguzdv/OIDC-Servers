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

        public AuthenticateResult AuthResult { get; set; }

        [Authorize]
        public async Task OnGet()
        {
            AuthResult = await HttpContext.AuthenticateAsync();
        }
    }
}