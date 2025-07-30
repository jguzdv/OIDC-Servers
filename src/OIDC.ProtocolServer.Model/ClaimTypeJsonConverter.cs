
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace JGUZDV.OIDC.ProtocolServer.Model;

public class ClaimTypeJsonConverter : JsonConverter<ClaimType>
{
    public override ClaimType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var type = reader.GetString();
        if (type == null)
        {
            throw new InvalidOperationException();
        }

        return new ClaimType(type);
    }
    public override void Write(Utf8JsonWriter writer, ClaimType value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.Type);
    }

    public override ClaimType ReadAsPropertyName(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var type = reader.GetString();
        if (type == null)
        {
            throw new InvalidOperationException();
        }

        return new ClaimType(type);
    }

    public override void WriteAsPropertyName(Utf8JsonWriter writer, [DisallowNull] ClaimType value, JsonSerializerOptions options)
    {
        writer.WritePropertyName(value.Type);
    }
}
