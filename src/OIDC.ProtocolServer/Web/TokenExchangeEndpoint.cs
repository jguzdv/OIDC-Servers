using System.Security.Claims;

using JGUZDV.OIDC.ProtocolServer.ActiveDirectory;
using JGUZDV.OIDC.ProtocolServer.OpenIddictExt;
using JGUZDV.OIDC.ProtocolServer.OpenTelemetry;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

using OpenIddict.Abstractions;

using OpenIddict.Server.AspNetCore;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.Web
{
    public partial class Endpoints
    {
        public partial class OIDC
        {
            /// <summary>
            /// This method is the "token endpoint" of the OIDC server. It's commonly called "exchange" in OIDC, probably because it exchanges some grant for tokens.
            /// It's used to determine the GrantType and then call the appropriate method to handle the grant.
            /// </summary>
            public static async Task<IResult> Exchange(
                HttpContext httpContext,
                UserValidationProvider userValidation,
                OIDCContextProvider oidcContextProvider,
                IdentityProvider identityProvider,
                ILogger<OIDC> logger,
                CancellationToken ct
            ) {
                try
                {
                    var oidcRequest = httpContext.GetOpenIddictServerRequest() ??
                        throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

                    IResult result;

                    if (oidcRequest.IsAuthorizationCodeGrantType())
                    {
                        result = await HandleAuthCodeExchange(httpContext, oidcRequest, ct);
                    }
                    else if (oidcRequest.IsRefreshTokenGrantType())
                    {
                        result = await HandleRefreshTokenExchange(httpContext, oidcRequest, userValidation, oidcContextProvider, identityProvider, ct);
                    }
                    else if (oidcRequest.IsClientCredentialsGrantType())
                    {
                        result = await HandleClientCredentialFlow(oidcRequest, oidcContextProvider, ct);
                    }
                    else
                    {
                        throw new InvalidOperationException("The specified grant type is not supported.");
                    }

                    LogResult(httpContext, logger, oidcRequest, result);
                    return result;

                }
                catch (Exception ex)
                {
                    // Log request and rethrow. 
                    LogMessages.TokenExchangeException(logger, ex,
                        httpContext?.Request?.GetDisplayUrl());

                    throw;
                }
            }

            private static void LogResult(HttpContext httpContext, ILogger<OIDC> logger, OpenIddictRequest oidcRequest, IResult? result)
            {
                switch (result)
                {
                    case SignInHttpResult signInHttpResult:
                        LogMessages.TokenExchangeFinished(logger,
                            oidcRequest?.ClientId,
                            signInHttpResult.Principal.FindFirstValue("zdv_upn"),
                            true,
                            signInHttpResult.Properties?.Items);
                        break;

                    case ForbidHttpResult forbidHttpResult:
                        LogMessages.TokenExchangeFinished(logger,
                            oidcRequest?.ClientId,
                            httpContext?.User?.FindFirstValue("upn"),
                            false,
                            forbidHttpResult.Properties?.Items);
                        break;

                    default:
                        LogMessages.UnexpectedExchangeHttpResultType(logger,
                            oidcRequest?.ClientId,
                            httpContext?.User?.FindFirstValue("upn"),
                            result?.GetType().FullName);
                        break;
                }
            }


            /// <summary>
            /// This handles the auth_code grant token generation.
            /// </summary>
            private static async Task<IResult> HandleAuthCodeExchange(
                HttpContext httpContext,
                OpenIddictRequest oidcRequest,
                CancellationToken ct)
            {
                if(!oidcRequest.IsAuthorizationCodeGrantType())
                {
                    throw new InvalidOperationException("This method should only be called for the authorization_code grant type.");
                }

                // Retrieve the claims principal stored in the authorization code.
                var authResult = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                if (!authResult.Succeeded)
                {
                    return InvalidGrant("The auth_code was invalid or already expired.");
                }

                var authenticatedUser = authResult.Principal;

                // If we're in a auth_code flow, we'll just return the user as is, since it's data should be fresh.
                return SignIn(authenticatedUser);
            }



            /// <summary>
            /// This handles the auth_code flow and the refresh_token flow token generation.
            /// </summary>
            private static async Task<IResult> HandleRefreshTokenExchange(
                HttpContext httpContext, 
                OpenIddictRequest oidcRequest,
                UserValidationProvider userValidation,
                OIDCContextProvider oidcContextProvider,
                IdentityProvider identityProvider,
                CancellationToken ct)
            {
                if (!oidcRequest.IsRefreshTokenGrantType())
                {
                    throw new InvalidOperationException("This method should only be called for the refresh_token grant type.");
                }

                // Retrieve the claims principal stored in the authorization code/refresh token.
                var authResult = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                if (!authResult.Succeeded)
                {
                    return InvalidGrant("The refresh token was invalid or already expired.");
                }


                var authenticatedUser = authResult.Principal;
                // If we're in a refresh_token flow, we'll do some checks and refresh the user data.
                {
                    // Check if the user account is still active
                    if (!userValidation.IsUserActive(authenticatedUser))
                    {
                        return InvalidGrant("The user is no longer active.");
                    }

                    // check if the password has changed _after_ refresh_token issuance
                    if (userValidation.LastPasswordChange(authenticatedUser) > authenticatedUser.GetCreationDate())
                    {
                        return InvalidGrant("The refresh token expired through password reset.");
                    }

                    var oidcContext = await oidcContextProvider.CreateContextAsync(oidcRequest, authenticatedUser.GetScopes(), ct);
                    
                    // Recreate the identity
                    var identity = await identityProvider.CreateIdentityAsync(authenticatedUser, oidcContext, ct);
                    identity.SetIdentityTokenLifetime(TimeSpan.FromSeconds(oidcContext.Application.Properties.MaxTokenLifetimeSeconds));

                    // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
                    return SignIn(new ClaimsPrincipal(identity));
                }


                // This should never be reached, as it's checked before this method is called, nevertheless, errors happen and we'll throw, if we get here.
                throw new InvalidOperationException("The specified grant type is not supported.");
            }


            /// <summary>
            /// This handles the client_credentials flow, which is a machine-to-machine flow.
            /// Obviously user claims will not be loaded here.
            /// </summary>
            private static async Task<IResult> HandleClientCredentialFlow(
                OpenIddictRequest oidcRequest, 
                OIDCContextProvider oidcContextProvider,
                CancellationToken ct)
            {
                if(!oidcRequest.IsClientCredentialsGrantType())
                {
                    throw new InvalidOperationException("This method should only be called for the client_credentials grant type.");
                }

                // OpenIddict will already have checked if client_id and client_secret is correct. So no explicit authentication is needed here.
                var requestedScopes = oidcRequest.GetScopes();
                var oidcContext = await oidcContextProvider.CreateContextAsync(oidcRequest, requestedScopes, ct);

                // Collect all static claims from application and scopes.
                var clientClaims = oidcContext.Application.Properties.StaticClaims
                    .Select(x => new Model.Claim(x.Type, x.Value))
                    .ToList();

                var scopeClaims = oidcContext.Scopes.SelectMany(x => x.Properties.StaticClaims)
                    .Select(x => new Model.Claim(x.Type, x.Value))
                    .ToList();


                var identity = new ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);


                // Add a subject and a name for good measure
                identity.SetClaim(Claims.Subject, oidcContext.Application.ClientId);
                identity.SetClaim(Claims.Name, oidcContext.Application.DisplayName);

                // Add the requested scopes and resources
                identity.SetScopes(requestedScopes);
                identity.SetResources(oidcContext.Scopes.SelectMany(x => x.Resources));

                // Add all static claims and set their destination to the access token
                identity.SetClaims(clientClaims.Concat(scopeClaims).DistinctBy(x => $"{x.Type.ToLowerInvariant()}:{x.Value.ToLowerInvariant()}"));
                identity.SetDestinations(x => [Destinations.AccessToken]);

                // Returning a SignInResult will ask OpenIddict to issue the appropriate access token.
                return SignIn(new ClaimsPrincipal(identity));
            }
        }

        private static IResult SignIn(ClaimsPrincipal principal)
            => Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        private static IResult InvalidGrant(string grantError)
            => Results.Forbid(
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = grantError
                })
            );

    }
}
