
using System.Text.Json.Serialization;

namespace JGUZDV.OIDC.ProtocolServer.Model;

public record Claim(ClaimType Type, ClaimValue Value)
{
    [JsonConstructor]
    public Claim(string type, string value)
        : this(new ClaimType(type), new ClaimValue(value))
    { }
}

