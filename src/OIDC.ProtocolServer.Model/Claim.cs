
using System.Text.Json;
using System.Text.Json.Serialization;

namespace JGUZDV.OIDC.ProtocolServer.Model;

[JsonConverter(typeof(ClaimJsonConverter))]
public record Claim(ClaimType Type, ClaimValue Value)
{
    [JsonConstructor]
    public Claim(string type, string value)
        : this(new ClaimType(type), new ClaimValue(value))
    { }
}

public class ClaimJsonConverter : JsonConverter<Claim>
{
    public override Claim Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? type = null;
        string? value = null;

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException();
        }

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                return type is not null && value is not null
                    ? new Claim(type, value)
                    : throw new JsonException("Did not find type and value in json deserialization");
            }

            if (reader.TokenType == JsonTokenType.PropertyName)
            {
                var propertyName = reader.GetString() ?? throw new JsonException();

                if (propertyName.Equals("Type", StringComparison.OrdinalIgnoreCase))
                {
                    ReadValue(ref type, ref reader);
                }
                else if (propertyName.Equals("Value", StringComparison.OrdinalIgnoreCase))
                {
                    ReadValue(ref value, ref reader);
                }
                else
                {
                    throw new JsonException();
                }
            }
            else
            {
                throw new JsonException();
            }
        }

        throw new JsonException();
    }

    private static void ReadValue(ref string? property, ref Utf8JsonReader reader)
    {
        reader.Read();
        property = reader.GetString();
    }

    public override void Write(Utf8JsonWriter writer, Claim value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteString("Type", value.Type.Type);
        writer.WriteString("Value", value.Value.Value);
        writer.WriteEndObject();
    }
}
