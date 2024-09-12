using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using JGUZDV.ActiveDirectory.Configuration;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.Configuration
{
    public class ProtocolServerOptions : IValidatableObject
    {
        [NotNull]
        public string? LdapServer { get; set; }

        [NotNull]
        public string? SubjectClaimType { get; set; }

        [NotNull]
        public string? PersonIdentifierClaimType { get; set; }

        public string? JGUDirectoryDatabaseConnectionString { get; set; }

        public string DefaultConsentType { get; set; } = ConsentTypes.Implicit;

        public Dictionary<string, string> Properties { get; set; } = new();
        public List<ClaimSource> ClaimSources { get; set; } = new();



        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (string.IsNullOrWhiteSpace(LdapServer))
            {
                yield return new("The LDAP server needs to be set.", [nameof(LdapServer)]);
            }

            if (string.IsNullOrWhiteSpace(SubjectClaimType))
            {
                yield return new("The user claim type needs to be set.", [nameof(SubjectClaimType)]);
            }
        }
    }
}
