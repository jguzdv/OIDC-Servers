using System.Text.Json;

using OpenIddict.Abstractions;

namespace JGUZDV.OIDC.ProtocolServer.Model
{
    public abstract class CustomProperties
    {
        protected static JsonSerializerOptions DefaultOptions => new()
        {
            PropertyNamingPolicy = null,
            PropertyNameCaseInsensitive = true,
            WriteIndented = true,
            Converters = { 
                new ClaimJsonConverter(),
                new ClaimTypeJsonConverter(), 
                new ClaimValueJsonConverter() 
            }
        };

        public const string PropertyName = "jgu-props";

        public abstract JsonElement Serialize();

        protected static T Deserialize<T>(JsonElement element)
            where T : CustomProperties, new()
        {
            return JsonSerializer.Deserialize<T>(element, DefaultOptions) ?? new();
        }

        public List<Claim> StaticClaims { get; set; } = new();
        public List<ClaimType> RequestedClaimTypes { get; set; } = new();

        public MFAProps MFA { get; set; } = new();
    }

    public class ApplicationProperties : CustomProperties
    {
        //Default = 8 hours
        public int MaxTokenLifetimeSeconds { get; set; } = 28800;

        public override JsonElement Serialize()
        {
            return JsonSerializer.SerializeToElement(this, DefaultOptions);
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
            return JsonSerializer.SerializeToElement(this, DefaultOptions);
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
