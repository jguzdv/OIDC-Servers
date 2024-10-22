using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

namespace JGUZDV.OIDC.ProtocolServer.Configuration;

public enum ClaimTransformationMethod
{
    PassThrough,
    Base64DecodeGuid,
}

public static class ClaimTransformationHelper
{
    [return:NotNullIfNotNull(nameof(value))]
    public static string? TransformValue(string? value, ClaimTransformationMethod method) =>
        method switch
        {
            ClaimTransformationMethod.Base64DecodeGuid => value is not null ? new Guid(Convert.FromBase64String(value)).ToString() : null,
            _ => value
        };

    public static string TransformValue(this Claim claim, ClaimTransformationMethod method)
        => TransformValue(claim.Value, method);

    public static Claim Transform(this Claim claim, ClaimTransformationMethod method, string? newClaimType = null) 
        => new Claim(newClaimType ?? claim.Type, TransformValue(claim.Value, method));
}