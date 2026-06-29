# JEAP OpenID Connect / OAuth2 Mock Server

OpenId Connect / OAuth2 Mock Server to use in automated tests and for local Development.

You may also provide a custom token customizer simply by providing a bean which
implements `OAuth2TokenCustomizer<JwtEncodingContext>`.
This is best done by extending from `AbstractJwtTokenCustomizer`, see `PamsJwtTokenCustomizer` for an example.

```
@Component
@RequiredArgsConstructor
public class MyTokenCustomizer extends AbstractJwtTokenCustomizer {

    /** Provides access to the client/user mock data */
    private final OAuthMockData oauthMockData; 

    @Override
    protected void customizeAccessToken(JwtEncodingContext context, Map<String, Object> claims) {
        // There is a convenience method in the base class to get the current client ID:
        String clientId = getClientIdFromSecurityContext();
        claims.put("custom", "value");
    }

    @Override
    protected void customizeIdToken(JwtEncodingContext context, Map<String, Object> claims) {
        claims.put("custom", "value");
    }
}
```

## Local Development with the `local-test` Profile

To run the mock server locally for development or manual testing, start the application with the `local-test` profile.
The server will be available at `http://localhost:8180/jeap-oauth-mock-server`.

### Accessing the Login Form

The login form at `/openIdMockServerLogin` cannot be accessed directly — it requires a saved OAuth authorization
request in the session. To reach the login form, initiate an authorization code flow by navigating to:

```
http://localhost:8180/jeap-oauth-mock-server/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=http://redirect&scope=openid&code_challenge=JBbiqONGWPaAmwXk_8bT6UnlPfrn65D32eZlJS-zGG0&code_challenge_method=S256
```

Spring Security will intercept the unauthenticated request and redirect you to the login form with the correct
client context.

> **Note:** The server requires PKCE with S256 ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)).
> The URL above uses a pre-computed challenge derived from the verifier `test-verifier`.

### Pre-configured Test Data (`local-test` profile)

| Parameter               | Value                                         |
|-------------------------|-----------------------------------------------|
| `client_id`             | `test-client`                                 |
| `redirect_uri`          | `http://redirect`                             |
| `scope`                 | `openid`                                      |
| `code_challenge`        | `JBbiqONGWPaAmwXk_8bT6UnlPfrn65D32eZlJS-zGG0` |
| `code_challenge_method` | `S256`                                        |

Two users are available: `user` (Henriette Muster) and `another-user` (Henry Muster).

## JWT signing key pair

JWTs signed by the server require a public/private key pair. The public key is exposed under the endpoint
`<baseurl>/.well-known/jwks.json` conforming to RFC 7517 (JSON Web Key).

The key is generated at startup and not persisted. Redeployment of the mock server will generate a new key pair, tokens
generated with the old key will not be valid anymore.

## Upgrading to a new Spring Security Authorization Server Version
The jEAP OAuth Mock Server is based on the Spring Security Authorization Server. Unfortunately, some authorization server classes
had to be patched to be able to provide the required functionality. When updating to a new authorization server version
those classes need to be updated, too. To do so follow the comments in the following classes:

 * InMemoryRegisteredClientRepository (allow non unique secrets per client registration)
 * SecurityConfig.validateScopeSupportingDynamicScopes (adding support for dynamic scopes in the auth code flow)
 * OAuth2ClientCredentialsAuthenticationProvider (adding support for dynamic scopes in the client credentials flow)

## Note

This repository is part the open source distribution of jEAP. See [github.com/jeap-admin-ch/jeap](https://github.com/jeap-admin-ch/jeap)
for more information.

## License

This repository is Open Source Software licensed under the [Apache License 2.0](./LICENSE).
