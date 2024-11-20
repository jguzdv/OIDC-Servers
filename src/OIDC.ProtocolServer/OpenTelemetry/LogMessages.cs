namespace JGUZDV.OIDC.ProtocolServer.OpenTelemetry
{
    internal static partial class LogMessages
    {
        [LoggerMessage(LogLevel.Information, "Run authorize request for client id: {oidc_clientId}")]
        public static partial void StartAuthorize(ILogger logger, string oidc_clientId);
    }
}
