using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

namespace JGUZDV.OIDC.ProtocolServer.Configuration
{
    public class JGUDirectoryClaimProviderOptions : IValidatableObject
    {
        [NotNull]
        public string? DatabaseConnectionString { get; set; }


        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (string.IsNullOrWhiteSpace(DatabaseConnectionString))
            {
                yield return new("The database connection string needs to be set.", [nameof(DatabaseConnectionString)]);
            }
        }
    }
}
