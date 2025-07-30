
using System.Text.Json;
using System.Text.Json.Serialization;

namespace JGUZDV.OIDC.ProtocolServer.Model;

public class ClaimValueJsonConverter : JsonConverter<ClaimValue>
{
    public override ClaimValue Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        if (value == null)
        {
            throw new InvalidOperationException();
        }

        return new ClaimValue(value);
    }
    public override void Write(Utf8JsonWriter writer, ClaimValue value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.Value);
    }
}