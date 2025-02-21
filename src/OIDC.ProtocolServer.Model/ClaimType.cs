using System.Text.Json.Serialization;

namespace JGUZDV.OIDC.ProtocolServer.Model;

[JsonConverter(typeof(ClaimTypeJsonConverter))]
public readonly record struct ClaimType(string Type)
{
    public readonly string Type
    {
        get;
        init
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value, nameof(value));
            field = value;
        }
    } = Type;

    public static implicit operator ClaimType(string claimType) => new(claimType);
}
