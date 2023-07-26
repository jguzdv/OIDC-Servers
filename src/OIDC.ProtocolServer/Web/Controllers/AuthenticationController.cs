using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JGUZDV.OIDC.ProtocolServer.Web.Controllers
{
    public class AuthenticationController : ControllerBase
    {
        [HttpGet("~/authn/login")]
        public IActionResult Login()
        {
            return Challenge();
        }

        [HttpGet("~/authn/logout")]
        public IActionResult Logout()
        {
            return SignOut();
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
    }
}
