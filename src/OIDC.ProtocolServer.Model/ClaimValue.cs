
namespace JGUZDV.OIDC.ProtocolServer.Model;

public struct ClaimValue : IEquatable<ClaimValue>
{
    public ClaimValue(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, nameof(value));

        Value = value;
    }

    public string Value { get; }

    public override bool Equals(object? obj)
    {
        return obj is ClaimValue value && Equals(value);
    }

    public bool Equals(ClaimValue other)
    {
        return Value == other.Value;
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Value);
    }

    public static bool operator ==(ClaimValue left, ClaimValue right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(ClaimValue left, ClaimValue right)
    {
        return !(left == right);
    }
}