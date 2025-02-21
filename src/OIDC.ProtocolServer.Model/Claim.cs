
namespace JGUZDV.OIDC.ProtocolServer.Model;

public record Claim
{
    public Claim(string type, string value)
    {
        Type = type ?? throw new ArgumentNullException(nameof(type));
        Value = value ?? throw new ArgumentNullException(nameof(value));
    }

    public string Type { get; init; }
    public string Value { get; init; }
}
