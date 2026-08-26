# Upgrading

The jEAP OAuth Mock Server is based on Spring Security Authorization Server. A few classes are intentionally patched to
provide behaviour that the upstream defaults do not provide.

When upgrading to a new Spring Security Authorization Server version, review the comments and diffs in these classes:

- `InMemoryRegisteredClientRepository` for allowing non-unique client secrets per client registration
- `SecurityConfig.validateScopeSupportingDynamicScopes(...)` for dynamic scopes in the authorization-code flow
- `org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider`
  for dynamic scopes in the client-credentials flow

Also regression-test these areas after the upgrade:

- login form redirect into `/openIdMockServerLogin`
- wildcard and localhost redirect URI validation
- dynamic `bproles:*` scope handling
- token introspection, especially with roles pruning enabled
- JWK output at `/.well-known/jwks.json`
