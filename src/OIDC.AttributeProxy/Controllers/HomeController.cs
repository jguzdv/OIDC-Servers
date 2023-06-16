using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JGUZDV.OIDC.AttributeProxy.Controllers
{
    public class HomeController : Controller
    {
        [Authorize]
        public async Task<IActionResult> Index()
        {
            var auth = await HttpContext.AuthenticateAsync();

            var result = auth.Properties.Items
                .Select(x => $"{x.Key} => {x.Value}\r\n")
                .Aggregate("", (x,c) => x+c);


            result += auth.Principal.Claims
                .Select(x => $"{x.Type}: {x.Value}\r\n")
                .Aggregate("", (x,c) => x+c);

            return Ok(result);
        }

        [AllowAnonymous, HttpGet("~/login")]
        public IActionResult Login()
        {
            return Challenge();
        }
    }
}
