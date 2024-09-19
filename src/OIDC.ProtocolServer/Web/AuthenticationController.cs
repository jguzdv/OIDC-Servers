using Microsoft.AspNetCore.Mvc;

namespace JGUZDV.OIDC.ProtocolServer.Web
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
    }
}
