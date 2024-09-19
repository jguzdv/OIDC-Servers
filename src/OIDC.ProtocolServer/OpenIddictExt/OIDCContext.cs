using System.Collections.Immutable;

using JGUZDV.OIDC.ProtocolServer.Model;

using OpenIddict.Abstractions;

namespace JGUZDV.OIDC.ProtocolServer.OpenIddictExt;

public record OIDCContext(OpenIddictRequest Request, ApplicationModel Application, ImmutableArray<ScopeModel> Scopes);
