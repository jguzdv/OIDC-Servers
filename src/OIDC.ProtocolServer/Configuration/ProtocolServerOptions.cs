﻿using System.Diagnostics.CodeAnalysis;

using JGUZDV.ActiveDirectory.ClaimProvider.Configuration;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JGUZDV.OIDC.ProtocolServer.Configuration
{
    public class ProtocolServerOptions
    {
        [NotNull]
        public string? UserClaimType { get; set; }
        public string DefaultConsentType { get; set; } = ConsentTypes.Implicit;

        public Dictionary<string, List<string>> ScopeClaims { get; set; } = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        public List<string> IdTokenClaims { get; set; } = new();

        public Dictionary<string, string> PropertyConverters { get; set; } = new();
        public List<ClaimSource> ClaimSources { get; set; } = new();
    }
}
