using System.Collections.Immutable;
using System.Globalization;
using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.ClaimProviders;
using JGUZDV.OIDC.ProtocolServer.Configuration;
using JGUZDV.OIDC.ProtocolServer.Data;
using JGUZDV.OIDC.ProtocolServer.Extensions;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

using static OpenIddict.Abstractions.OpenIddictConstants;

using Claim = System.Security.Claims.Claim;

namespace JGUZDV.OIDC.ProtocolServer.Web.Controllers;

public class ConnectController(
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictAuthorizationManager authorizationManager,
    IOpenIddictScopeManager scopeManager,
    TimeProvider timeProvider,
    IOptions<ProtocolServerOptions> options) : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager = applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager = authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager = scopeManager;
    private readonly TimeProvider _timeProvider = timeProvider;
    private readonly IOptions<ProtocolServerOptions> _options = options;

    private readonly ISet<string> _remoteClaimTypes = new HashSet<string>()
    {
        Claims.AuthenticationMethodReference,
        "mfa_auth_time"
    };

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize(
        [FromServices]IEnumerable<IClaimProvider> claimProviders,
        CancellationToken ct)
    {
        var oidcRequest = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var application = await ApplicationModel.FromClientIdAsync(_applicationManager, oidcRequest.ClientId!, ct);
        var scopes = await ScopeModel.FromScopeNamesAsync(_scopeManager, oidcRequest.GetScopes(), ct);
        
        if ((await CheckIfChallengeIsNeededAsync(oidcRequest, application, scopes)) is IActionResult challengeResult)
            return challengeResult;

        var userId = User.GetClaim(_options.Value.UserClaimType) ??
            throw new InvalidOperationException($"The user is missing the claim {_options.Value.UserClaimType}.");


        // Retrieve the permanent authorizations associated with the user and the calling client application.
        var authorizations = await _authorizationManager.FindAsync(
                subject: userId,
                client: application.Id,
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: oidcRequest.GetScopes(),
                cancellationToken: ct
            ).ToListAsync(ct);

        if (CheckIfConsentIsNeeded(oidcRequest, application, authorizations) is IActionResult consentResult)
            return consentResult;

        
        // Create the claims-based identity that will be used by OpenIddict to generate tokens.
        var identity = await CreateIdentityAsync(
            oidcRequest, userId, application, scopes, authorizations, claimProviders, ct);
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }


    [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> Exchange(
        [FromServices] IEnumerable<IClaimProvider> claimProviders,
        [FromServices] UserValidationProvider userValidation, 
        CancellationToken ct)
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            throw new InvalidOperationException("The specified grant type is not supported.");


        // Retrieve the claims principal stored in the authorization code/refresh token.
        var authResult = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (!authResult.Succeeded)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The refresh token was invalid or already expired."
                }));
        }

        var user = authResult.Principal;
        if (!userValidation.IsUserActive(user))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer active."
                }));
        }

        // check if the password has changed _after_ refresh_token issuance
        if (userValidation.LastPasswordChange(user) > User.GetCreationDate())
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The refresh token expired through password reset."
                }));
        }

        var identity = new ClaimsIdentity(user.Claims,
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

        var scopes = await ScopeModel.FromScopeNamesAsync(_scopeManager, identity.GetScopes(), ct);
        var idClaims = scopes
            .Where(x => x.Properties.TargetToken.Contains(Destinations.IdentityToken))
            .SelectMany(x => x.Properties.RequestedClaimTypes)
            .Concat(_remoteClaimTypes)
            .ToHashSet();

        var userClaims = new List<(string Type, string Value)>();
        foreach (var cp in claimProviders)
        {
            var claims = await cp.GetClaimsAsync(user, idClaims.Distinct(), ct);
            userClaims.AddRange(claims);
        }

        foreach (var claimType in userClaims.GroupBy(x => x.Type))
        {
            if (claimType.Count() > 1)
                identity.SetClaim(claimType.Key, claimType.First().Value);
            else
                identity.SetClaims(claimType.Key, claimType.Select(x => x.Value).ToImmutableArray());
        }

        identity.SetDestinations(x => GetDestinations(x, idClaims));

        // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }


    //    [Authorize, FormValueRequired("submit.Accept")]
    //    [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
    //    public async Task<IActionResult> Accept()
    //    {
    //        var request = HttpContext.GetOpenIddictServerRequest() ??
    //            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

    //        // Retrieve the profile of the logged in user.
    //        var user = await _userManager.GetUserAsync(User) ??
    //            throw new InvalidOperationException("The user details cannot be retrieved.");

    //        // Retrieve the application details from the database.
    //        var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
    //            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

    //        // Retrieve the permanent authorizations associated with the user and the calling client application.
    //        var authorizations = await _authorizationManager.FindAsync(
    //            subject: await _userManager.GetUserIdAsync(user),
    //            client: await _applicationManager.GetIdAsync(application),
    //            status: Statuses.Valid,
    //            type: AuthorizationTypes.Permanent,
    //            scopes: request.GetScopes()).ToListAsync();

    //        // Note: the same check is already made in the other action but is repeated
    //        // here to ensure a malicious user can't abuse this POST-only endpoint and
    //        // force it to return a valid response without the external authorization.
    //        if (!authorizations.Any() && await _applicationManager.HasConsentTypeAsync(application, ConsentTypes.External))
    //        {
    //            return Forbid(
    //                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
    //                properties: new AuthenticationProperties(new Dictionary<string, string>
    //                {
    //                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
    //                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
    //                        "The logged in user is not allowed to access this client application."
    //                }));
    //        }

    //        // Create the claims-based identity that will be used by OpenIddict to generate tokens.
    //        var identity = new ClaimsIdentity(
    //            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
    //            nameType: Claims.Name,
    //            roleType: Claims.Role);

    //        // Add the claims that will be persisted in the tokens.
    //        identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
    //                .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
    //                .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
    //                .SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());

    //        // Note: in this sample, the granted scopes match the requested scope
    //        // but you may want to allow the user to uncheck specific scopes.
    //        // For that, simply restrict the list of scopes before calling SetScopes.
    //        identity.SetScopes(request.GetScopes());
    //        identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

    //        // Automatically create a permanent authorization to avoid requiring explicit consent
    //        // for future authorization or token requests containing the same scopes.
    //        var authorization = authorizations.LastOrDefault();
    //        authorization ??= await _authorizationManager.CreateAsync(
    //            identity: identity,
    //            subject: await _userManager.GetUserIdAsync(user),
    //            client: await _applicationManager.GetIdAsync(application),
    //            type: AuthorizationTypes.Permanent,
    //            scopes: identity.GetScopes());

    //        identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
    //        identity.SetDestinations(GetDestinations);

    //        // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
    //        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    //    }

    //    [Authorize, FormValueRequired("submit.Deny")]
    //    [HttpPost("~/connect/authorize"), ValidateAntiForgeryToken]
    //    // Notify OpenIddict that the authorization grant has been denied by the resource owner
    //    // to redirect the user agent to the client application using the appropriate response_mode.
    //    public IActionResult Deny() => Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

    //    [HttpGet("~/connect/logout")]
    //    public IActionResult Logout() => View();

    //    [ActionName(nameof(Logout)), HttpPost("~/connect/logout"), ValidateAntiForgeryToken]
    //    public async Task<IActionResult> LogoutPost()
    //    {
    //        // Ask ASP.NET Core Identity to delete the local and external cookies created
    //        // when the user agent is redirected from the external identity provider
    //        // after a successful authentication flow (e.g Google or Facebook).
    //        await _signInManager.SignOutAsync();

    //        // Returning a SignOutResult will ask OpenIddict to redirect the user agent
    //        // to the post_logout_redirect_uri specified by the client application or to
    //        // the RedirectUri specified in the authentication properties if none was set.
    //        return SignOut(
    //            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
    //            properties: new AuthenticationProperties
    //            {
    //                RedirectUri = "/"
    //            });
    //    }


    // --- Private methods --- //

    private static readonly IEnumerable<string> BothTokens = [Destinations.IdentityToken, Destinations.AccessToken];
    private static readonly IEnumerable<string> AccessToken = [Destinations.AccessToken];

    private static IEnumerable<string> GetDestinations(Claim claim, HashSet<string> idTokenClaims)
    {
        return idTokenClaims.Contains(claim.Type, StringComparer.OrdinalIgnoreCase) 
            ? BothTokens : AccessToken;
    }


    private async Task<IActionResult?> CheckIfChallengeIsNeededAsync(
        OpenIddictRequest oidcRequest,
        ApplicationModel application, 
        ImmutableArray<ScopeModel> scopes)
    {
        var authenticationResult = await HttpContext.AuthenticateAsync();

        // Try to retrieve the user principal stored in the authentication cookie and redirect
        // the user agent to the login page (or to an external provider) in the following cases:
        //
        //  - If the user principal can't be extracted or the cookie is too old.

        bool requestNeedsMFA = false;
        var needsChallenge = authenticationResult?.Succeeded != true 
            || HasLoginPromptOrIsTooOld() 
            || (requestNeedsMFA = NeedsMFAChallange());
            
        if (needsChallenge)
        {
            // If the client application requested promptless authentication,
            // return an error indicating that the user is not logged in.
            if (oidcRequest.HasPrompt(Prompts.None))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                    }));
            }

            // To avoid endless login -> authorization redirects, the prompt=login flag
            // is removed from the authorization request payload before redirecting the user.
            var prompt = string.Join(" ", oidcRequest.GetPrompts().Remove(Prompts.Login));

            var parameters = Request.HasFormContentType ?
                Request.Form.Where(parameter => parameter.Key != Parameters.Prompt).ToList() :
                Request.Query.Where(parameter => parameter.Key != Parameters.Prompt).ToList();

            parameters.Add(KeyValuePair.Create(Parameters.Prompt, new StringValues(prompt)));

            return Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(parameters)
                },
                requestNeedsMFA ? Constants.AuthenticationSchemes.MFA : Constants.AuthenticationSchemes.OIDC);
        }

        return null;


        bool HasLoginPromptOrIsTooOld()
        {
            //  If a max_age parameter was provided and the authentication cookie is not considered "fresh" enough.
            //  If prompt=login was specified by the client application and the login is older than 5 minutes (else, we'll ignore that prompt)

            var issuedAt = authenticationResult?.Properties?.IssuedUtc ?? DateTimeOffset.MinValue;
            var maxAge = oidcRequest.HasPrompt(Prompts.Login)
                ? TimeSpan.FromMinutes(5)
                : oidcRequest.MaxAge != null
                    ? TimeSpan.FromSeconds(oidcRequest.MaxAge.Value)
                    : TimeSpan.MaxValue;

            return _timeProvider.GetUtcNow() - issuedAt > maxAge;
        }

        bool NeedsMFAChallange()
        {
            var mfaRequirements = scopes
                .Where(x => x.Properties.MFA.Required)
                .Select(x => x.Properties.MFA);

            if(application.Properties.MFA.Required)
                mfaRequirements = mfaRequirements.Append(application.Properties.MFA);

            if (!mfaRequirements.Any())
                return false;

            // Check if the user has mfa'd already
            if(User?.FindFirstValue(Constants.ClaimTypes.MFAAuthTime) is not string mfaAuthTimeValue)
                return true;

            // Check if any MFA requirement has a max age
            if(!mfaRequirements.Any(x => x.MaxAge.HasValue))
                return false;

            // Convert mfaAuthTime from string to DateTimeOffset
            var mfaAuthTimeEpoch = long.Parse(mfaAuthTimeValue, NumberStyles.Integer, CultureInfo.InvariantCulture);
            var mfaAuthTime = DateTimeOffset.FromUnixTimeSeconds(mfaAuthTimeEpoch);

            var maxAge = mfaRequirements
                .Where(x => x.MaxAge.HasValue)
                .Select(x => x.MaxAge!.Value)
                .Min();

            // The users MFA claim is too old
            return _timeProvider.GetUtcNow() - mfaAuthTime > maxAge;
        }
    }

    private async Task<ClaimsIdentity> CreateIdentityAsync(
        OpenIddictRequest oidcRequest, string userId,
        ApplicationModel application, IEnumerable<ScopeModel> requestedScopes,
        List<object> authorizations, IEnumerable<IClaimProvider> claimProviders,
        CancellationToken ct)
    {
        var requestedClaims = CollectRequestedClaimTypes(application, requestedScopes);

        var userClaims = new List<(string Type, string Value)>();
        foreach (var cp in claimProviders)
        {
            var claims = await cp.GetClaimsAsync(User, requestedClaims.Distinct(), ct);
            userClaims.AddRange(claims);
        }


        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        foreach (var c in userClaims)
        {
            identity.SetClaim(c.Type, c.Value);
        }

        foreach (var remoteClaim in User.Claims.Where(x => _remoteClaimTypes.Contains(x.Type)))
        {
            identity.AddClaim(remoteClaim.Type, remoteClaim.Value);
        }

        // Note: in this sample, the granted scopes match the requested scope
        // but you may want to allow the user to uncheck specific scopes.
        // For that, simply restrict the list of scopes before calling SetScopes.
        identity.SetScopes(requestedScopes.Select(x => x.Name));
        identity.SetResources(requestedScopes.SelectMany(x => x.Resources));

        // Automatically create a permanent authorization to avoid requiring explicit consent
        // for future authorization or token requests containing the same scopes.
        var authorization = authorizations.LastOrDefault();
        authorization ??= await _authorizationManager.CreateAsync(
            identity: identity,
            subject: userId,
            client: application.Id,
            type: AuthorizationTypes.Permanent,
            scopes: oidcRequest.GetScopes(),
            cancellationToken: ct);

        var idTokenClaims = requestedScopes
            .Where(x => x.Properties.TargetToken.Contains(Destinations.IdentityToken))
            .SelectMany(x => x.Properties.RequestedClaimTypes)
            .Concat(_remoteClaimTypes)
            .ToHashSet();

        var authorizationId = await _authorizationManager.GetIdAsync(authorization, ct);
        identity.SetAuthorizationId(authorizationId);
        identity.SetDestinations(c => GetDestinations(c, idTokenClaims));

        return identity;
    }


    private static HashSet<string> CollectRequestedClaimTypes(ApplicationModel application, 
        IEnumerable<ScopeModel> requestedScopes)
    {
        return requestedScopes
            .SelectMany(x => x.Properties.RequestedClaimTypes)
            .Concat(application.Properties.RequestedClaimTypes)
            .ToHashSet();
    }


    private IActionResult? CheckIfConsentIsNeeded(OpenIddictRequest oidcRequest,
        ApplicationModel application, List<object> authorizations)
    {
        switch (application.ConsentType)
        {
            // If the consent is external (e.g when authorizations are granted by a sysadmin),
            // immediately return an error if no authorization can be found in the database.
            case ConsentTypes.External when !authorizations.Any():
                return ConsentError("The logged in user is not allowed to access this client application.");

            // If the consent is implicit or if an authorization was found,
            // return an authorization response without displaying the consent form.
            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Any():
            case ConsentTypes.Explicit when authorizations.Any() && !oidcRequest.HasPrompt(Prompts.Consent):
                return null;

            // At this point, no authorization was found in the database and an error must be returned
            // if the client application specified prompt=none in the authorization request.
            case ConsentTypes.Explicit when oidcRequest.HasPrompt(Prompts.None):
            case ConsentTypes.Systematic when oidcRequest.HasPrompt(Prompts.None):
                return ConsentError("Interactive user consent is required.");
        }

        return View(new
        {
            ApplicationName = application,
            Scope = oidcRequest.Scope
        });
    }

    private IActionResult ConsentError(string consentError)
        => Forbid(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = consentError
            })
        );

}
