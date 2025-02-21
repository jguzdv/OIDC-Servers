
namespace JGUZDV.OIDC.ProtocolServer.Model;

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
}

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