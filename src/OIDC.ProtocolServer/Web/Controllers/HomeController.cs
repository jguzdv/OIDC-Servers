using Azure.Core;
using System.Diagnostics;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace JGUZDV.OIDC.ProtocolServer.Web.Controllers
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

            var result = auth.Properties.Items
                .Select(x => $"{x.Key} => {x.Value}\r\n")
                .Aggregate("", (x, c) => x + c);


            result += auth.Principal.Claims
                .Select(x => $"{x.Type}: {x.Value}\r\n")
                .Aggregate("", (x, c) => x + c);

            return Ok(result);
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
