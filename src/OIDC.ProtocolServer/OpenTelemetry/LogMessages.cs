using Microsoft.Extensions.Primitives;

namespace JGUZDV.OIDC.ProtocolServer.OpenTelemetry
{
    internal static partial class LogMessages
    {
        [LoggerMessage(LogLevel.Information, "Run authorize request for client id {oidc_clientId} with requested scopes {oidc_requested_scopes}")]
        public static partial void StartAuthorize(ILogger logger, string oidc_clientId, IEnumerable<string> oidc_requested_scopes);

        [LoggerMessage(LogLevel.Information, "Found user during authorization process: Iss: {oidc_iss}, upn: {oidc_upn}, clientId: {oidc_clientId}")]
        public static partial void UserFound(ILogger logger, string? oidc_iss, string? oidc_upn, string oidc_clientId);

        [LoggerMessage(LogLevel.Error, "Unexpected exception during the authorize request. RequestUrl: {oidc_requestUrl} User?: Name: {oidc_name}, upn: {oidc_upn}")]
        public static partial void AuthException(ILogger logger, Exception exception, string? oidc_requestUrl, string? oidc_name, string? oidc_upn);

        [LoggerMessage(LogLevel.Error, "Unexpected exception during token exchange. RequestUrl: {oidc_requestUrl}")]
        public static partial void TokenExchangeException(ILogger logger, Exception exception, string? oidc_requestUrl);

        [LoggerMessage(LogLevel.Information, "Trigger challange redirect for application {oidc_application} with parameters {oidc_parameters}, clientId {oidc_clientId}")]
        public static partial void TriggerChallange(ILogger logger, string oidc_application, List<KeyValuePair<string, StringValues>>? oidc_parameters, string oidc_clientId);

        [LoggerMessage(LogLevel.Information, "Token exchange: Exchange process finished. ClientId: {oidc_clientId}, upn: {oidc_upn}, success: {oidc_success}, properties: {oidc_properties}")]
        public static partial void TokenExchangeFinished(ILogger logger, string? oidc_clientId, string? oidc_upn, bool oidc_success, IDictionary<string, string?>? oidc_properties);

        [LoggerMessage(LogLevel.Error, "Unexpected result type at TokenExchangeEndpoint: ClientId: {oidc_clientId}, upn: {oidc_upn}, result type: {oidc_result_type_name}")]
        public static partial void UnexpectedExchangeHttpResultType(ILogger logger, string? oidc_clientId, string? oidc_upn, string? oidc_result_type_name);
    }
}
