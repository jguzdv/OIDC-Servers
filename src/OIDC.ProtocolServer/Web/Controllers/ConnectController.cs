using System.Collections.Immutable;
using System.Globalization;
using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.ActiveDirectory;
using JGUZDV.OIDC.ProtocolServer.ClaimProviders;
using JGUZDV.OIDC.ProtocolServer.Configuration;
using JGUZDV.OIDC.ProtocolServer.Model;
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
using static System.Net.Mime.MediaTypeNames;
using Microsoft.AspNetCore.Identity;
using System.Security.Principal;

namespace JGUZDV.OIDC.ProtocolServer.Web.Controllers;

public class ConnectController(
    IOpenIddictAuthorizationManager authorizationManager,
    IOpenIddictApplicationManager applicationManager,
    IOpenIddictScopeManager scopeManager,
    IEnumerable<IClaimProvider> claimProviders,
    UserValidationProvider userValidation,
    TimeProvider timeProvider,
    IOptions<ProtocolServerOptions> options) : Controller
{
    private readonly IOpenIddictAuthorizationManager _authorizationManager = authorizationManager;
    private readonly IOpenIddictApplicationManager _applicationManager = applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager = scopeManager;

    private readonly IEnumerable<IClaimProvider> _claimProviders = claimProviders;
    private readonly UserValidationProvider _userValidation = userValidation;
    private readonly TimeProvider _timeProvider = timeProvider;
    private readonly IOptions<ProtocolServerOptions> _options = options;

    //TODO: would probably be better to have this in the options
    private readonly ISet<string> _remoteClaimTypes = new HashSet<string>()
    {
        Claims.AuthenticationMethodReference,
        Constants.ClaimTypes.MFAAuthTime
    };

    private static readonly IEnumerable<string> BothTokens = [Destinations.IdentityToken, Destinations.AccessToken];
    private static readonly IEnumerable<string> AccessToken = [Destinations.AccessToken];

    /// <summary>
    /// This method gets called, when the user is redirected to the authorize endpoint.
    /// It will check if the request is a valid OIDC request, load the application and scopes.
    /// The user will be challenged if necessary and the consent will be checked.
    /// If everything is fine, the user will be signed in.
    /// </summary>
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize(CancellationToken ct)
    {
        // Retrieve the OpenID Connect request from the HttpContext - this is provided by OpenIddict
        var oidcRequest = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Retrieve the application and scopes from the request
        var (application, scopes) = await GetApplicationAndScopesAsync(oidcRequest.ClientId!, oidcRequest.GetScopes(), ct);

        // Check if the user needs to be challenged, if this method returns an action result, we'll return it.
        var challengeResult = await GetChallengeIfNeededAsync(oidcRequest, application, scopes);
        if (challengeResult is not null)
        {
            return challengeResult;
        }


        // If we got this far, the user is authenticated and we can retrieve the user id from the claims.
        // The claims here are "remote" to the application, since they are provided by another authentication provider (see Program.cs).
        var authenticatedUser = User;
        var subject = authenticatedUser.GetClaim(_options.Value.SubjectClaimType) ??
            throw new InvalidOperationException($"The user is missing the claim {_options.Value.SubjectClaimType}.");


        // We might have application that are configured to ask for user consent. If this function returns an action result, we'll return it.
        var consentResult = await GetConsentIfNeededAsync(oidcRequest, application, oidcRequest.GetScopes(), subject, ct);
        if (consentResult is not null)
        {
            return consentResult;
        }

        
        // Create the claims-based identity that will be used by OpenIddict to generate tokens.
        var identity = await CreateIdentityAsync(authenticatedUser, application, scopes, ct);

        // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }


    /// <summary>
    /// 
    /// </summary>
    [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
    public async Task<IActionResult> Exchange(CancellationToken ct)
    {
        var oidcRequest = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (oidcRequest.IsAuthorizationCodeGrantType() || oidcRequest.IsRefreshTokenGrantType())
        {
            return await HandleAuthCodeOrRefreshTokenExchange(oidcRequest, ct);
        }

        if (oidcRequest.IsClientCredentialsGrantType())
        {
            return await HandleClientCredentialFlow(oidcRequest, ct);
        }
        
        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    /// <summary>
    /// This handles the auth_code flow and the refresh_token flow token generation.
    /// </summary>
    private async Task<IActionResult> HandleAuthCodeOrRefreshTokenExchange(OpenIddictRequest oidcRequest, CancellationToken ct)
    {
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

        var authenticatedUser = authResult.Principal;
        if (!_userValidation.IsUserActive(authenticatedUser))
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
        if (_userValidation.LastPasswordChange(authenticatedUser) > authenticatedUser.GetCreationDate())
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The refresh token expired through password reset."
                }));
        }


        // If we're in a auth_code flow, we'll just return the user as is, since it's data should be fresh.
        if (oidcRequest.IsAuthorizationCodeGrantType())
        {
            return SignIn(authenticatedUser, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // If we're in a refresh_token flow, we'll need to refresh the user data.
        if (oidcRequest.IsRefreshTokenGrantType())
        {
            // Retrieve the application and scopes from the request
            var (application, scopes) = await GetApplicationAndScopesAsync(oidcRequest.ClientId!, authenticatedUser.GetScopes(), ct);

            // Recreate the identity
            var identity = await CreateIdentityAsync(authenticatedUser, application, scopes, ct);

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // This should never be reached, as it's checked before this method is called.
        throw new InvalidOperationException("The specified grant type is not supported.");
    }


    /// <summary>
    /// This handles the client_credentials flow, which is a machine-to-machine flow.
    /// Obviously user claims will not be loaded here.
    /// </summary>
    private async Task<IActionResult> HandleClientCredentialFlow(OpenIddictRequest oidcRequest, CancellationToken ct)
    {
        var requestedScopes = oidcRequest.GetScopes();
        var (application, scopes) = await GetApplicationAndScopesAsync(oidcRequest.ClientId!, requestedScopes, ct);

        // Collect all static claims from application and scopes.
        var clientClaims = application.Properties.StaticClaims
            .Select(x => (x.Type, x.Value))
            .ToList();

        var scopeClaims = scopes.SelectMany(x => x.Properties.StaticClaims)
            .Select(x => (x.Type, x.Value))
            .ToList();

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, application.ClientId);
        identity.SetClaim(Claims.Name, application.DisplayName);

        identity.SetScopes(requestedScopes);
        identity.SetResources(scopes.SelectMany(x => x.Resources));

        SetClaims(identity, clientClaims.Union(scopeClaims));
        identity.SetDestinations(x => AccessToken);

        // Returning a SignInResult will ask OpenIddict to issue the appropriate access token.
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
    private static IEnumerable<string> GetDestinations(Claim claim, HashSet<string> idTokenClaims)
    {
        return idTokenClaims.Contains(claim.Type, StringComparer.OrdinalIgnoreCase) 
            ? BothTokens : AccessToken;
    }


    private async Task<(ApplicationModel application, ImmutableArray<ScopeModel> scopes)> GetApplicationAndScopesAsync(string clientId, ImmutableArray<string> scopeNames, CancellationToken ct)
    {
        var application = await ApplicationModel.FromClientIdAsync(_applicationManager, clientId, ct);
        var scopes = await ScopeModel.FromScopeNamesAsync(_scopeManager, scopeNames, ct);

        if(scopeNames.Contains(Scopes.OfflineAccess))
        {
            scopes = scopes.Add(new ScopeModel(Scopes.OfflineAccess, Scopes.OfflineAccess, [], new()));
        }

        return (application, scopes);
    }


    /// <summary>
    /// Checks if a challenge or mfa-challange is needed and creates a challenge result if necessary.
    /// If this method returns null, no challange is needed.
    /// </summary>
    private async Task<IActionResult?> GetChallengeIfNeededAsync(
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
            || (requestNeedsMFA = NeedsMFAChallenge());
            
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

        bool NeedsMFAChallenge()
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

    private async Task<ClaimsIdentity> CreateIdentityAsync(ClaimsPrincipal subject,
        ApplicationModel application, IEnumerable<ScopeModel> requestedScopes, 
        CancellationToken ct)
    {
        // Determine, which claims are requested by the client application and to which token they should be added.
        // Also collect "resources" (=> Audience) that are requested by the client application.
        var idTokenClaims = new HashSet<string>(application.Properties.RequestedClaimTypes);
        var accessTokenClaims = new HashSet<string>();
        var resources = new HashSet<string>();

        foreach (var scope in requestedScopes)
        {
            if (scope.Properties.TargetToken.Contains(Destinations.IdentityToken))
                idTokenClaims.UnionWith(scope.Properties.RequestedClaimTypes);

            //TODO: if (scope.Properties.TargetToken.Contains(Destinations.AccessToken))
            accessTokenClaims.UnionWith(scope.Properties.RequestedClaimTypes);

            resources.UnionWith(scope.Resources);
        }

        // Load all claims that are requested by the client application
        var requestedClaims = new HashSet<string>(idTokenClaims.Concat(accessTokenClaims));
        var subjectClaims = await LoadSubjectClaims(subject, requestedClaims, ct);


        // Create the claims-based identity that will be used by OpenIddict to generate tokens.
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        // Add scope and audience claims
        // Note: The granted scopes match the requested scope
        // but you may want to allow the user to uncheck specific scopes.
        // For that, simply restrict the list of scopes before calling SetScopes.
        identity.SetScopes(requestedScopes.Select(x => x.Name));
        identity.SetResources(requestedScopes.SelectMany(x => x.Resources));


        // Copy claims from the remote identity to the new identity
        foreach (var remoteClaim in User.Claims.Where(x => _remoteClaimTypes.Contains(x.Type)))
        {
            identity.AddClaim(remoteClaim.Type, remoteClaim.Value);
        }

        SetClaims(identity, subjectClaims);

        // Currently _all_ claims will be added to the access token and _some_ claims will be added to the id token.
        identity.SetDestinations(c => GetDestinations(c, idTokenClaims));

        return identity;
    }

    private static void SetClaims(ClaimsIdentity identity, IEnumerable<(string Type, string Value)> claims)
    {
        // Claims may be single value or multi value. So we group by type and add them accordingly.
        foreach (var claimTypeClaims in claims.GroupBy(x => x.Type, StringComparer.OrdinalIgnoreCase))
        {
            if (claimTypeClaims.Count() == 1)
            {
                identity.SetClaim(claimTypeClaims.Key, claimTypeClaims.First().Value);
            }
            else
            {
                identity.SetClaims(claimTypeClaims.Key, claimTypeClaims.Select(x => x.Value).Distinct().ToImmutableArray());
            }
        }
    }

    private async Task<List<(string Type, string Value)>> LoadSubjectClaims(ClaimsPrincipal subject, HashSet<string> requestedClaims, CancellationToken ct)
    {
        var userClaims = new List<(string Type, string Value)>();
        foreach (var cp in _claimProviders)
        {
            var claims = await cp.GetClaimsAsync(subject, requestedClaims, ct);
            userClaims.AddRange(claims);
        }

        return userClaims;
    }

    private static HashSet<string> CollectRequestedClaimTypes(ApplicationModel application, 
        IEnumerable<ScopeModel> requestedScopes)
    {
        return requestedScopes
            .SelectMany(x => x.Properties.RequestedClaimTypes)
            .Concat(application.Properties.RequestedClaimTypes)
            .ToHashSet();
    }



    private async Task<IActionResult?> GetConsentIfNeededAsync(OpenIddictRequest oidcRequest,
        ApplicationModel application, ImmutableArray<string> scopes, string subject, CancellationToken ct)
    {
        // Retrieve the permanent authorizations associated with the user and the calling client application.
        var authorizations = await _authorizationManager.FindAsync(
                subject: subject,
                client: application.Id,
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: oidcRequest.GetScopes(),
                cancellationToken: ct
            ).ToListAsync(ct);

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
