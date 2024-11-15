using System.Diagnostics.Metrics;
using JGUZDV.AspNetCore.Extensions.OpenTelemetry;

using Microsoft.Extensions.Options;

namespace OIDC.ProtocolServer.OpenTelemetry;

public class MeterContainer : AbstractJguZdvMeter
{
    private readonly Counter<int> _exampleCounter;


    public MeterContainer(IOptions<AspNetCoreOpenTelemetryOptions> options) : base(options)
    {
        _exampleCounter = Meter.CreateCounter<int>(
            name: "webapp.example.count",
            description: "Example counter");
    }


    public void CountExample()
    {
        _exampleCounter.Add(1,
            KeyValuePair.Create("example", (object?)"example"));
    }
}
