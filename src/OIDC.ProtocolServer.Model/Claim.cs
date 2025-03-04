
using System.Text.Json;
using System.Text.Json.Serialization;

namespace JGUZDV.OIDC.ProtocolServer.Model;

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

        for (int i = 0; i < 2; i++)
        {
            if (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    var propertyName = reader.GetString() ?? "-";

                    if(propertyName.Equals("Type", StringComparison.OrdinalIgnoreCase))
                    {
                        reader.Read();
                        type = reader.GetString();
                    }
                    else if (propertyName.Equals("Value", StringComparison.OrdinalIgnoreCase))
                    {
                        reader.Read();
                        value = reader.GetString();
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
            else
            {
                throw new JsonException();
            }
        }

        if(type is null || value is null)
        {
            throw new JsonException();
        }

        return new Claim(type, value);
    }
    public override void Write(Utf8JsonWriter writer, Claim value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteString("Type", value.Type.Type);
        writer.WriteString("Value", value.Value.Value);
        writer.WriteEndObject();
    }
}
