
using System.Text.Json.Serialization;

namespace JGUZDV.OIDC.ProtocolServer.Model;

[JsonConverter(typeof(ClaimValueJsonConverter))]
public readonly record struct ClaimValue(string Value)
{
    public readonly string Value
    {
        get;
        init
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value, nameof(value));
            field = value;
        }
    } = Value;
}