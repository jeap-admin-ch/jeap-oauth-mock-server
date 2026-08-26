# Client integration examples

This page shows typical ways to point local applications at the mock server.

## Angular UI with `angular-auth-oidc-client`

Example `auth.clientConfiguration.json`:

```json
{
  "production": false,
  "authWellknownEndpointUrl": "http://localhost:8180/jeap-oauth-mock-server/.well-known/openid-configuration",
  "config": {
    "authority": "http://localhost:8180/jeap-oauth-mock-server",
    "redirectUrl": "http://localhost:4200/startpage",
    "postLogoutRedirectUri": "http://localhost:4200/",
    "clientId": "example-ui",
    "scope": "openid profile email",
    "responseType": "code",
    "silentRenew": false,
    "useRefreshToken": false
  }
}
```

Make sure the `clientId` and redirect URI match the mock-server client configuration.

## Spring OAuth2 client using `client_credentials`

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          example-client:
            authorization-grant-type: client_credentials
            client-id: example-service
            client-secret: secret
            scope: testscope
        provider:
          example-client:
            issuer-uri: http://localhost:8180/jeap-oauth-mock-server
```

The mock server accepts standard Spring Security client configuration. Use `issuer-uri` so Spring discovers the token
endpoint from the OpenID configuration.

## Spring resource server

A resource server can validate tokens from the mock server like any other JWT issuer:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8180/jeap-oauth-mock-server

jeap:
  security:
    oauth2:
      resourceserver:
        jwt:
          validation:
            contextissuers:
              USER:
                issuer: http://localhost:8180/jeap-oauth-mock-server
              SYS:
                issuer: http://localhost:8180/jeap-oauth-mock-server
```

If your service distinguishes `USER` and `SYS` contexts, map both to the same mock-server issuer for local
integration tests.

## Token introspection

The mock server also supports token introspection and reconstructs pruned role claims in introspection responses.
This is useful when testing clients that rely on introspection rather than JWT decoding.

## Debug logging

For troubleshooting OAuth flows, enable Spring Security logging:

```yaml
logging:
  level:
    org.springframework.security: DEBUG
    org.springframework.security.oauth2.server: TRACE
    org.springframework.web: DEBUG
    ch.admin.bit.jeap: DEBUG
```

## Related topics

- [Getting started](getting-started.md)
- [Configuration](configuration.md)
