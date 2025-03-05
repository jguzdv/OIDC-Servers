using System.Text.Json;

using JGUZDV.OIDC.ProtocolServer.Model;

namespace OIDC.ProtocolServer.Model.Tests
{
    public class JsonConverterTests
    {
        [Fact]
        public void Can_Serialize_and_Deserialize_Claim()
        {
            var claim = new Claim("type", "value");
            var json = JsonSerializer.Serialize(claim);
            var deserialized = JsonSerializer.Deserialize<Claim>(json);

            Assert.NotNull(deserialized);
            Assert.Equal(claim.Type, deserialized.Type);
            Assert.Equal(claim.Value, deserialized.Value);
        }
    }
}
