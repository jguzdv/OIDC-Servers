using System.Text.Json;

using OpenIddict.Abstractions;

namespace JGUZDV.OIDC.ProtocolServer.Data
{
    public abstract class CustomProperties
    {
        public const string PropertyName = "jgu-props";

        public JsonElement Serialize()
        {
            return JsonSerializer.SerializeToElement(this);
        }

        protected static T Deserialize<T>(JsonElement element)
            where T : CustomProperties, new()
        {
            return JsonSerializer.Deserialize<T>(element) ?? new();
        }

        public List<Claim> StaticClaims { get; set; } = new();
        public List<string> RequestedClaimTypes { get; set; } = new();
    }

    public class ApplicationProperties : CustomProperties
    {
        public static ApplicationProperties DeserializeFromProperties(IDictionary<string, JsonElement> properties)
        {
            return properties.TryGetValue(PropertyName, out var json)
                ? Deserialize<ApplicationProperties>(json) 
                : new();
        }
    }

    public class ScopeProperties : CustomProperties
    {
        public static ScopeProperties DeserializeFromProperties(IDictionary<string, JsonElement> properties)
        {
            return properties.TryGetValue(PropertyName, out var json) 
                ? Deserialize<ScopeProperties>(json) 
                : new();
        }

        public List<string> TargetToken { get; set; } = new() { OpenIddictConstants.Destinations.AccessToken };
    }
}
