using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace JGUZDV.OIDC.ProtocolServer.Data
{
    public abstract class CommonProperties
    {
        [return:NotNullIfNotNull("fallbackValue")]
        public static TResult? DeserializeElement<TResult>(
            IImmutableDictionary<string, JsonElement>? properties, 
            string key, TResult? fallbackValue)
        {
            if(properties == null)
                return fallbackValue;

            if(properties.TryGetValue(key, out var jsonElement))
            {
                try
                {
                    return jsonElement.Deserialize<TResult>() ?? fallbackValue;
                }
                catch {}
            }

            return fallbackValue;
        }

        public CommonProperties(IImmutableDictionary<string, JsonElement>? properties)
        {
            if (properties == null)
                return;

            ClaimTypes = DeserializeElement<List<string>>(properties, Constants.Properties.ClaimTypes, new());
            StaticClaims = DeserializeElement<List<(string Type, string Value)>>(properties, Constants.Properties.StaticClaims, new());
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
            IsIdTokenScope = DeserializeElement<bool>(properties, Constants.Properties.IsIdTokenScope, false);
        }

        public bool IsIdTokenScope { get; set; }
    }
}
