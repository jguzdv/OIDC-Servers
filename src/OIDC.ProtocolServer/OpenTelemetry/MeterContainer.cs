using System.Diagnostics.Metrics;
using JGUZDV.AspNetCore.Extensions.OpenTelemetry;
using JGUZDV.OIDC.ProtocolServer.Model;

using Microsoft.Extensions.Options;

namespace OIDC.ProtocolServer.OpenTelemetry;

public class MeterContainer : AbstractJguZdvMeter
{
    private readonly Counter<int> _oidcAuthorizeClientCounter;


    public MeterContainer(IOptions<AspNetCoreOpenTelemetryOptions> options) : base(options)
    {
        _oidcAuthorizeClientCounter = Meter.CreateCounter<int>(
            name: "oidc.protocol.server.authorize.client.count",
            description: "Counter for oidc authorize requests.");
    }

    /// <summary>
    /// customMetrics
    /// | where timestamp > ago(24h)
    /// | where name == "oidc.protocol.server.authorize.client.count"
    /// | extend oidcClientId = customDimensions.oidc_client_id
    /// </summary>
    /// <param name="clientId"></param>
    public void CountAuthorizeRequestByClient(string clientId, IEnumerable<ScopeModel> scopes)
    {        
        _oidcAuthorizeClientCounter.Add(1,
            KeyValuePair.Create("oidc_client_id", (object?)clientId),
            KeyValuePair.Create("oidc_scopes", (object?)string.Join(" ", scopes)));
    }
}
