
using System.Text.Json;
using System.Text.Json.Serialization;

namespace JGUZDV.OIDC.ProtocolServer.Model;

public class ClaimValueJsonConverter : JsonConverter<ClaimValue>
{
    public override ClaimValue Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return new ClaimValue(reader.GetString());
    }
    public override void Write(Utf8JsonWriter writer, ClaimValue value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.Value);
    }
}