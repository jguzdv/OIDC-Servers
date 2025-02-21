
namespace JGUZDV.OIDC.ProtocolServer.Model;

public record Claim(ClaimType Type, ClaimValue Value)
{
    public Claim(string type, string value)
        : this(new ClaimType(type), new ClaimValue(value))
    { }
}

