using System.Diagnostics;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JGUZDV.OIDC.ProtocolServer.Web
{
    public class HomeController : Controller
    {
        [HttpGet("~/")]
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet("~/Error")]
        public IActionResult Error()
        {
            return View(new ErrorModel(HttpContext));
        }

        [HttpGet("~/self")]
        [Authorize]
        public async Task<IActionResult> WhoAmI()
        {
            var auth = await HttpContext.AuthenticateAsync();
            return View(auth);
        }

        [HttpGet("~/self-mfa")]
        [Authorize(AuthenticationSchemes = Constants.AuthenticationSchemes.MFA)]
        public async Task<IActionResult> WhoAmIMFA()
        {
            var auth = await HttpContext.AuthenticateAsync();
            return View(auth);
        }

        public class ErrorModel
        {
            public string? RequestId { get; set; }

            public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

            public ErrorModel(HttpContext httpContext)
            {
                RequestId = Activity.Current?.Id ?? httpContext.TraceIdentifier;
            }
        }
    }
}
