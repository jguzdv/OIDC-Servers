using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

using OpenIddict.Server.AspNetCore;

namespace JGUZDV.OIDC.ProtocolServer.Web
{
    public class EndSessionController : Controller
    {
        [Route("/connect/endsession"), HttpGet()]
        public IActionResult Index()
        {
            var model = Request.HasFormContentType
                ? Request.Form.ToDictionary(x => x.Key, x => x.Value)
                : Request.Query.ToDictionary(x => x.Key, x => x.Value);

            return View(model);
        }

        [Route("/connect/endsession"), HttpPost()]
        public async Task<IActionResult> Post()
        {
            await HttpContext.SignOutAsync();

            // Returning a SignOutResult will ask OpenIddict to redirect the user agent
            // to the post_logout_redirect_uri specified by the client application or to
            // the RedirectUri specified in the authentication properties if none was set.
            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "/"
                });
        }
    }
}
