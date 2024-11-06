# JGUZDV.OIDC.ProtocolServer

Based upon OpenIdDict, this protocol server is intendet to provide OIDC Services for our environments.
It's highly opinionated and won't handle authentication itself, but rely on another server that'll be chained.

The server assumes an ActiveDirectory and will load requested attributes via ldap and transform them into claims.

