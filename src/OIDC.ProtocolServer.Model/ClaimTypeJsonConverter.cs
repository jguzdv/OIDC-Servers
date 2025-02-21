
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace JGUZDV.OIDC.ProtocolServer.Model;

public class ClaimTypeJsonConverter : JsonConverter<ClaimType>
{
    public override ClaimType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return new ClaimType(reader.GetString());
    }
    public override void Write(Utf8JsonWriter writer, ClaimType value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.Type);
    }

    public override ClaimType ReadAsPropertyName(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return new ClaimType(reader.GetString());
    }

    public override void WriteAsPropertyName(Utf8JsonWriter writer, [DisallowNull] ClaimType value, JsonSerializerOptions options)
    {
        writer.WritePropertyName(value.Type);
    }
}
