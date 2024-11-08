using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

namespace JGUZDV.OIDC.ProtocolServer.Configuration;

public class PrincipalClaimProviderOptions : IValidatableObject
{
    public List<PrincipalClaimType> ClaimTypeMaps { get; set; } = new();


    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        foreach (var claimType in ClaimTypeMaps)
        {
            foreach (var result in claimType.Validate(validationContext))
            {
                yield return result;
            }
        }
    }


    public class PrincipalClaimType : IValidatableObject
    {
        [NotNull]
        public string? ClaimType { get; set; }

        public string? AsClaimType { get; set; }

        public ClaimTransformationMethod Transformation { get; set; } = default;

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (string.IsNullOrWhiteSpace(ClaimType))
            {
                yield return new("The claim type needs to be set.", [nameof(ClaimType)]);
            }
        }
    }
}
