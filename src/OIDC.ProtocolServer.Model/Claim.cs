﻿
namespace JGUZDV.OIDC.ProtocolServer.Model
{
    public class Claim // TODO: this should probably be a record
    {
        public Claim(string type, string value)
        {
            Type = type ?? throw new ArgumentNullException(nameof(type));
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public string Type { get; }
        public string Value { get; }
    }
}
