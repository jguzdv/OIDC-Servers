using System.Collections.Immutable;
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

namespace JGUZDV.OIDC.ProtocolServer.Web.Controllers;

public class ConnectController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;

    private readonly IOptions<ProtocolServerOptions> _options;

    public ConnectController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        IOptions<ProtocolServerOptions> options)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;

        _options = options;
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize([FromServices]IEnumerable<IClaimProvider> claimProviders,
        CancellationToken ct)
    {
        var oidcRequest = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var authenticationResult = await HttpContext.AuthenticateAsync();

        var challengeResult = DetermineChallengeResult(oidcRequest, authenticationResult);
        if (challengeResult != null)
            return challengeResult;

        var application = ApplicationModel.FromClientId(_applicationManager, oidcRequest.ClientId!, ct);
        

        var clientUuid = await _applicationManager.GetIdAsync(application, ct);

        var userId = User.GetClaim(_options.Value.UserClaimType) ??
            throw new InvalidOperationException($"The user is missing the claim {_options.Value.UserClaimType}.");


        // Retrieve the permanent authorizations associated with the user and the calling client application.
        var authorizations = await _authorizationManager.FindAsync(
                subject: userId,
                client: clientUuid!,
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: oidcRequest.GetScopes(),
                cancellationToken: ct
            ).ToListAsync(ct);

        var consentType = (await _applicationManager.GetConsentTypeAsync(application, ct)) ?? _options.Value.DefaultConsentType;
        var (needsConsent, consentError) = CheckConsent(oidcRequest, authorizations, consentType);

        if (consentError != null)
        {
            return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = consentError
                    })
                );
        }

        if (needsConsent)
        {
            return View(new
            {
                ApplicationName = await _applicationManager.GetLocalizedDisplayNameAsync(application),
                Scope = oidcRequest.Scope
            });
        }


        // Create the claims-based identity that will be used by OpenIddict to generate tokens.
        var identity = await CreateIdentityAsync(
            oidcRequest, userId, clientUuid!, 
            application, authorizations, claimProviders, ct);
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<ClaimsIdentity> CreateIdentityAsync(
        OpenIddictRequest oidcRequest, string userId,
        ApplicationModel application, List<object> authorizations, IEnumerable<IClaimProvider> claimProviders, 
        CancellationToken ct)
    {
        var requestedScopes = oidcRequest.GetScopes();
        var (requestedClaims, scopeClaims) = await CollectRequestedClaimTypes(application, requestedScopes, ct);

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

        // Note: in this sample, the granted scopes match the requested scope
        // but you may want to allow the user to uncheck specific scopes.
        // For that, simply restrict the list of scopes before calling SetScopes.
        identity.SetScopes(oidcRequest.GetScopes());
        identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync(ct));

        // Automatically create a permanent authorization to avoid requiring explicit consent
        // for future authorization or token requests containing the same scopes.
        var authorization = authorizations.LastOrDefault();
        authorization ??= await _authorizationManager.CreateAsync(
            identity: identity,
            subject: userId,
            client: clientUuid,
            type: AuthorizationTypes.Permanent,
            scopes: oidcRequest.GetScopes());

        var idTokenClaims = requestedScopes
            .Intersect(_options.Value.IdTokenScopes)
            .Select(scopeClaims.GetValueOrDefault)
            .Where(x => x != null)
            .SelectMany(x => x!.ClaimTypes)
            .ToHashSet();

        identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
        identity.SetDestinations(c => GetDestinations(c, idTokenClaims));

        return identity;
    }

    private async Task<HashSet<string>> CollectRequestedClaimTypes(ApplicationModel application, IEnumerable<ScopeModel> requestedScopes, CancellationToken ct)
    {
        return requestedScopes
            .SelectMany(x => x.RequestedClaimTypes)
            .Concat(application.RequestedClaimTypes)
            .ToHashSet();
    }

    private (bool needsConsent, string? consentError) CheckConsent(OpenIddictRequest oidcRequest, List<object> authorizations, string consentType)
    {
        switch (consentType)
        {
            // If the consent is external (e.g when authorizations are granted by a sysadmin),
            // immediately return an error if no authorization can be found in the database.
            case ConsentTypes.External when !authorizations.Any():
                return (true, "The logged in user is not allowed to access this client application.");

            // If the consent is implicit or if an authorization was found,
            // return an authorization response without displaying the consent form.
            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Any():
            case ConsentTypes.Explicit when authorizations.Any() && !oidcRequest.HasPrompt(Prompts.Consent):
                return (false, null);

            // At this point, no authorization was found in the database and an error must be returned
            // if the client application specified prompt=none in the authorization request.
            case ConsentTypes.Explicit when oidcRequest.HasPrompt(Prompts.None):
            case ConsentTypes.Systematic when oidcRequest.HasPrompt(Prompts.None):
                return (true, "Interactive user consent is required.");
        }

        return (true, null);
    }

    private IActionResult? DetermineChallengeResult(OpenIddictRequest oidcRequest, AuthenticateResult authenticationResult)
    {
        // Try to retrieve the user principal stored in the authentication cookie and redirect
        // the user agent to the login page (or to an external provider) in the following cases:
        //
        //  - If the user principal can't be extracted or the cookie is too old.
        //  - If a max_age parameter was provided and the authentication cookie is not considered "fresh" enough.
        //  - If prompt=login was specified by the client application
        //    and the login is older than 5 minutes (else, we'll ignore that prompt)
        var issuedAt = authenticationResult?.Properties?.IssuedUtc ?? DateTimeOffset.MinValue;
        var maxAge = oidcRequest.HasPrompt(Prompts.Login)
            ? TimeSpan.FromMinutes(5)
            : oidcRequest.MaxAge != null
                ? TimeSpan.FromSeconds(oidcRequest.MaxAge.Value)
                : TimeSpan.MaxValue;

        var needsChallenge = authenticationResult?.Succeeded != true || DateTimeOffset.UtcNow - issuedAt > maxAge;
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
                });
        }

        return null;
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

    [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> Exchange([FromServices] UserValidationProvider userValidation, CancellationToken ct)
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // Retrieve the claims principal stored in the authorization code/refresh token.
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            if (!userValidation.IsUserActive(User))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer active."
                    }));
            }

            if()


            // TODO: check if the password has changed _after_ refresh_token issuance
            // Ensure the user is still allowed to sign in.
            //if (!await _signInManager.CanSignInAsync(user))
            //{
            //    return Forbid(
            //        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            //        properties: new AuthenticationProperties(new Dictionary<string, string?>
            //        {
            //            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
            //            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The refresh token expired through password reset."
            //        }));
            //}

            var identity = new ClaimsIdentity(result.Principal.Claims,
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            //// Override the user claims present in the principal in case they
            //// changed since the authorization code/refresh token was issued.
            //identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
            //        .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
            //        .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user))
            //        .SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());

            //identity.SetDestinations(GetDestinations);

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    private static readonly IEnumerable<string> BothTokens = new[] { Destinations.IdentityToken, Destinations.AccessToken };
    private static readonly IEnumerable<string> AccessToken = new[] { Destinations.AccessToken };

    private IEnumerable<string> GetDestinations(Claim claim, HashSet<string> idTokenClaims)
    {
        return idTokenClaims.Contains(claim.Type, StringComparer.OrdinalIgnoreCase) 
            ? BothTokens 
            : AccessToken;
    }
}
