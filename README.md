# JEAP OpenID Connect / OAuth2 Mock Server

OpenId Connect / OAuth2 Mock Server to use in automated tests and for local Development.

You may also provide a custom token customizer simply by providing a bean which
implements `OAuth2TokenCustomizer<JwtEncodingContext>`.
This is best done by extending from `AbstractJwtTokenCustomizer`, see `PamsJwtAccessTokenCustomizer` for an example.

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

## Generating a JWT signing key pair

JWTs signed by the server require a public/private key pair. The public key is exposed
under `<baseurl>/.well-known/jwks.json`
for resource servers wishing to validate the signature of JWTs issued by the mock server.

The key is stored under `src/main/resources/mockserver.jks`, and has been generated using

    keytool -genkeypair -alias mockserver -keyalg RSA -keypass secret -keystore mockserver.jks -storepass secret

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
