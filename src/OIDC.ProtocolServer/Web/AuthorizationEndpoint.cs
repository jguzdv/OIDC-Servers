using System.Collections.Immutable;
using System.Globalization;
using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.Configuration;
using JGUZDV.OIDC.ProtocolServer.Extensions;
using JGUZDV.OIDC.ProtocolServer.Logging;
using JGUZDV.OIDC.ProtocolServer.OpenIddictExt;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

using OIDC.ProtocolServer.OpenTelemetry;

using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.Web;

public partial class Endpoints
{
    public partial class OIDC
    {
        /// <summary>
        /// This method gets called, when the user is redirected to the authorize endpoint.
        /// It will check if the request is a valid OIDC request, load the application and scopes.
        /// The user will be challenged if necessary and the consent will be checked.
        /// If everything is fine, the user will be signed in.
        /// </summary>
        public static async Task<IResult> Authorize(
            HttpContext httpContext, 
            OIDCContextProvider contextProvider,
            IdentityProvider identityProvider,
            IOptions<ProtocolServerOptions> options,
            IOpenIddictAuthorizationManager authorizationManager,
            TimeProvider timeProvider,
            MeterContainer meterContainer,
            ILogger<OIDC> logger,
            CancellationToken ct
            )
        {
            try
            {
                // Retrieve the OpenID Connect request from the HttpContext - this is provided by OpenIddict
                var oidcRequest = httpContext.GetOpenIddictServerRequest() ??
                    throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

                var oidcContext = await contextProvider.CreateContextAsync(oidcRequest, httpContext.RequestAborted);

                // Log the requested clientId, so we can create some statistics about used clients.
                logger.LogInformation("Run authorize request for client id: {oidc_clientId}", oidcContext.Application.ClientId);
                meterContainer.CountAuthorizeRequestByClient(oidcContext.Application.ClientId);

                // Check if the user needs to be challenged, if this method returns an action result, we'll return it.
                var challengeResult = await GetChallengeIfNeededAsync(httpContext, oidcContext, timeProvider, logger);
                if (challengeResult is not null)
                {
                    return challengeResult;
                }


                // If we got this far, the user is authenticated and we can retrieve the user id from the claims.
                // The claims here are "remote" to the application, since they are provided by another authentication provider (see Program.cs).
                var authenticatedUser = httpContext.User;
                var subject = GetUniqueClaimValue(authenticatedUser, options.Value.SubjectClaimType);

                logger.LogInformation("Found user during authorization process: " +
                    "Iss: {oidc_iss}, upn: {oidc_upn}, clientId: {oidc_clientId}",
                    authenticatedUser?.FindFirstValue("iss"), authenticatedUser?.FindFirstValue("upn"),
                    oidcContext.Application.ClientId);

                // We might have application that are configured to ask for user consent. If this function returns an action result, we'll return it.
                var consentResult = await GetConsentIfNeededAsync(subject, oidcContext, authorizationManager, ct);
                if (consentResult is not null)
                {
                    return consentResult;
                }

                // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                var identity = await identityProvider.CreateIdentityAsync(authenticatedUser, oidcContext, ct);
                identity.SetIdentityTokenLifetime(TimeSpan.FromSeconds(oidcContext.Application.Properties.MaxTokenLifetimeSeconds));

                // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
                return Results.SignIn(new ClaimsPrincipal(identity), authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }
            catch (Exception ex)
            {
                // Log and rethrow. Give some context if possible.
                logger.LogError(ex, "Unexpected exception during the authorize request. " +
                    "RequestUrl: {oidc_requestUrl} " +
                    "User?: Name: {oidc_name}, zdv_upn: {oidc_zdvUpn}",
                    httpContext.Request.GetDisplayUrl(),
                    httpContext.User?.FindFirstValue("Name"), httpContext?.User?.FindFirstValue("zdv_upn"));

                throw;
            }
        }


        private static string GetUniqueClaimValue(ClaimsPrincipal principal, string claimType)
        {
            var claimValues = principal.GetClaims(claimType)
                .Distinct()
                .ToImmutableArray();
            
            if (claimValues.Length != 1)
            {
                throw new InvalidOperationException($"The unique claim type {claimType} was found {claimValues.Length} times.");
            }

            return claimValues[0];
        }

        /// <summary>
        /// Checks if a challenge or mfa-challange is needed and creates a challenge result if necessary.
        /// If this method returns null, no challange is needed.
        /// </summary>
        private static async Task<IResult?> GetChallengeIfNeededAsync(
            HttpContext httpContext,
            OIDCContext oidcContext,
            TimeProvider timeProvider,
            ILogger logger)
        {
            var authenticationResult = await httpContext.AuthenticateAsync();

            // Try to retrieve the user principal stored in the authentication cookie and redirect
            // the user agent to the login page (or to an external provider) in the following cases:
            //
            //  - If the user principal can't be extracted or the cookie is too old.

            bool requestNeedsMFA = false;
            var needsChallenge = authenticationResult?.Succeeded != true
                || HasLoginPromptOrIsTooOld()
                || (requestNeedsMFA = NeedsMFAChallenge(authenticationResult.Principal));

            if (needsChallenge)
            {
                // If the client application requested promptless authentication,
                // return an error indicating that the user is not logged in.
                if (oidcContext.Request.HasPrompt(Prompts.None))
                {
                    return Results.Forbid(
                        authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                        }));
                }

                // To avoid endless login -> authorization redirects, the prompt=login flag
                // is removed from the authorization request payload before redirecting the user.
                var prompt = string.Join(" ", oidcContext.Request.GetPrompts().Remove(Prompts.Login));

                var parameters = httpContext.Request.HasFormContentType ?
                    httpContext.Request.Form.Where(parameter => parameter.Key != Parameters.Prompt).ToList() :
                    httpContext.Request.Query.Where(parameter => parameter.Key != Parameters.Prompt).ToList();

                parameters.Add(KeyValuePair.Create(Parameters.Prompt, new StringValues(prompt)));

                logger.LogInformation("Trigger challange redirect for application {oidc_application} " +
                    "with parameters {oidc_parameters}, clientId {oidc_clientId}.", 
                    oidcContext.Application.DisplayName, parameters, oidcContext.Application.ClientId);

                return Results.Challenge(
                    authenticationSchemes: [requestNeedsMFA ? Constants.AuthenticationSchemes.MFA : Constants.AuthenticationSchemes.OIDC],
                    properties: new AuthenticationProperties
                    {
                        RedirectUri = httpContext.Request.PathBase + httpContext.Request.Path + QueryString.Create(parameters)
                    }
                );
            }

            return null;


            bool HasLoginPromptOrIsTooOld()
            {
                //  If a max_age parameter was provided and the authentication cookie is not considered "fresh" enough.
                //  If prompt=login was specified by the client application and the login is older than 5 minutes (else, we'll ignore that prompt)

                var issuedAt = authenticationResult?.Properties?.IssuedUtc ?? DateTimeOffset.MinValue;
                var maxAge = oidcContext.Request.HasPrompt(Prompts.Login)
                    ? TimeSpan.FromMinutes(5)
                    : oidcContext.Request.MaxAge != null
                        ? TimeSpan.FromSeconds(oidcContext.Request.MaxAge.Value)
                        : TimeSpan.MaxValue;

                return timeProvider.GetUtcNow() - issuedAt > maxAge;
            }

            bool NeedsMFAChallenge(ClaimsPrincipal? user)
            {
                var mfaRequirements = oidcContext.Scopes
                    .Where(x => x.Properties.MFA.Required)
                    .Select(x => x.Properties.MFA);

                if (oidcContext.Application.Properties.MFA.Required)
                    mfaRequirements = mfaRequirements.Append(oidcContext.Application.Properties.MFA);

                if (!mfaRequirements.Any())
                    return false;

                // Check if the user has mfa'd already
                if (user?.FindFirstValue(Constants.ClaimTypes.MFAAuthTime) is not string mfaAuthTimeValue)
                    return true;

                // Check if any MFA requirement has a max age
                if (!mfaRequirements.Any(x => x.MaxAge.HasValue))
                    return false;

                // Convert mfaAuthTime from string to DateTimeOffset
                var mfaAuthTimeEpoch = long.Parse(mfaAuthTimeValue, NumberStyles.Integer, CultureInfo.InvariantCulture);
                var mfaAuthTime = DateTimeOffset.FromUnixTimeSeconds(mfaAuthTimeEpoch);

                var maxAge = mfaRequirements
                    .Where(x => x.MaxAge.HasValue)
                    .Select(x => x.MaxAge!.Value)
                    .Min();

                // The users MFA claim is too old
                return timeProvider.GetUtcNow() - mfaAuthTime > maxAge;
            }
        }


        /// <summary>
        /// Checks if user consent is needed and creates a redirect result if necessary.
        /// If this method returns null, no consent is needed.
        /// </summary>
        private static async Task<IResult?> GetConsentIfNeededAsync(
            string subject,
            OIDCContext oidcContext,
            IOpenIddictAuthorizationManager authorizationManager,
            CancellationToken ct
        ) {
            // Retrieve the permanent authorizations associated with the user and the calling client application.
            var authorizations = await authorizationManager.FindAsync(
                    subject: subject,
                    client: oidcContext.Application.Id,
                    status: Statuses.Valid,
                    type: AuthorizationTypes.Permanent,
                    scopes: oidcContext.Request.GetScopes(),
                    cancellationToken: ct
                ).ToListAsync(ct);

            switch (oidcContext.Application.ConsentType)
            {
                // If the consent is external (e.g when authorizations are granted by a sysadmin),
                // immediately return an error if no authorization can be found in the database.
                case ConsentTypes.External when !authorizations.Any():
                    return ConsentError("The logged in user is not allowed to access this client application.");

                // If the consent is implicit or if an authorization was found,
                // return an authorization response without displaying the consent form.
                case ConsentTypes.Implicit:
                case ConsentTypes.External when authorizations.Any():
                case ConsentTypes.Explicit when authorizations.Any() && !oidcContext.Request.HasPrompt(Prompts.Consent):
                    return null;

                // At this point, no authorization was found in the database and an error must be returned
                // if the client application specified prompt=none in the authorization request.
                case ConsentTypes.Explicit when oidcContext.Request.HasPrompt(Prompts.None):
                case ConsentTypes.Systematic when oidcContext.Request.HasPrompt(Prompts.None):
                    return ConsentError("Interactive user consent is required.");
            }

            // TODO: Redirect to Consent page
            //return View(new
            //{
            //    ApplicationName = application,
            //    Scope = oidcRequest.Scope
            //});
            throw new NotImplementedException("User consent is not implemented yet.");
        }

        private static IResult ConsentError(string consentError)
            => Results.Forbid(
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = consentError
                })
            );
    }
}
