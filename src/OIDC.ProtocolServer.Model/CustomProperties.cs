using System.Text.Json;

using OpenIddict.Abstractions;

namespace JGUZDV.OIDC.ProtocolServer.Model
{
    public abstract class CustomProperties
    {
        public const string PropertyName = "jgu-props";

        public abstract JsonElement Serialize();

        protected static T Deserialize<T>(JsonElement element)
            where T : CustomProperties, new()
        {
            return JsonSerializer.Deserialize<T>(element) ?? new();
        }

        public List<Claim> StaticClaims { get; set; } = new();
        public List<string> RequestedClaimTypes { get; set; } = new();

        public MFAProps MFA { get; set; } = new();
    }

    public class ApplicationProperties : CustomProperties
    {
        //Default = 8 hours
        public int MaxTokenLifetimeSeconds { get; set; } = 28800;

        public override JsonElement Serialize()
        {
            return JsonSerializer.SerializeToElement(this);
        }

        public static ApplicationProperties DeserializeFromProperties(IDictionary<string, JsonElement> properties)
        {
            return properties.TryGetValue(PropertyName, out var json)
                ? Deserialize<ApplicationProperties>(json) 
                : new();
        }
    }

    public class ScopeProperties : CustomProperties
    {
        public override JsonElement Serialize()
        {
            return JsonSerializer.SerializeToElement(this);
        }

        public static ScopeProperties DeserializeFromProperties(IDictionary<string, JsonElement> properties)
        {
            return properties.TryGetValue(PropertyName, out var json) 
                ? Deserialize<ScopeProperties>(json) 
                : new();
        }

        public HashSet<string> TargetToken { get; set; } = new() { OpenIddictConstants.Destinations.AccessToken };
    }
}
