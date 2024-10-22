using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using JGUZDV.ActiveDirectory.Configuration;

namespace JGUZDV.OIDC.ProtocolServer.Configuration
{
    // TODO: Reflect changes of options into the implementation here.
    public class ActiveDirectoryClaimProviderOptions : IValidatableObject
    {
        [NotNull]
        public string? LdapServer { get; set; }


        public Dictionary<string, string> Properties { get; set; } = new();
        public List<ClaimSource> ClaimSources { get; set; } = new();


        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (string.IsNullOrWhiteSpace(LdapServer))
            {
                yield return new("The LDAP server needs to be set.", [nameof(LdapServer)]);
            }
        }
    }
}
