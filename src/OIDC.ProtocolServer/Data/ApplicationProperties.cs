using System.Collections.Immutable;
using System.Text.Json;

namespace JGUZDV.OIDC.ProtocolServer.Data
{
    public static class Constants {
        public static class Properties
        {
            public const string ClaimTypes = "claimTypes";
            public const string StaticClaims = "staticClaims";
        }
    }

    public abstract class CommonProperties
    {
        public CommonProperties(IImmutableDictionary<string, JsonElement>? properties)
        {
            if (properties == null)
                return;

            if(properties.TryGetValue(Constants.Properties.ClaimTypes, out var claimTypesElement))
            {
                try
                {
                    ClaimTypes = claimTypesElement.Deserialize<List<string>>() ?? new();
                }
                catch { }
            }

            if (properties.TryGetValue(Constants.Properties.StaticClaims, out var staticClaimsElement))
            {
                try
                {
                    StaticClaims = staticClaimsElement.Deserialize<List<(string Type, string Value)>>() ?? new();
                }
                catch { }
            }
        }

        public List<(string Type, string Value)> StaticClaims { get; set; } = new();
        public List<string> ClaimTypes { get; set; } = new();
    }

    public class ApplicationProperties : CommonProperties
    {
        public ApplicationProperties(IImmutableDictionary<string, JsonElement>? properties) 
            : base(properties)
        { 

        }
    }

    public class ScopeProperties : CommonProperties
    {
        public ScopeProperties(IImmutableDictionary<string, JsonElement>? properties)
            : base(properties)
        {

        }
    }
}
