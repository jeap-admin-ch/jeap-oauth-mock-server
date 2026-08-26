# Custom token claims

The mock server uses `PamsJwtTokenCustomizer` as its default token mapper. You can replace it by providing your own
`OAuth2TokenCustomizer<JwtEncodingContext>` bean.

The recommended approach is to extend `AbstractJwtTokenCustomizer`, which already gives you access to configured clients
and users and provides helpers such as `getClientIdFromSecurityContext()`, `requireClient(...)`, and
`requireUser(...)`.

## Example

```java
@Component
@RequiredArgsConstructor
public class MyTokenCustomizer extends AbstractJwtTokenCustomizer {

    /** Provides access to the client/user mock data */
    private final OAuthMockData oauthMockData;

    @Override
    protected void customizeAccessToken(JwtEncodingContext context, Map<String, Object> claims) {
        String clientId = getClientIdFromSecurityContext();
        claims.put("custom", "value");
    }

    @Override
    protected void customizeIdToken(JwtEncodingContext context, Map<String, Object> claims) {
        claims.put("custom", "value");
    }
}
```

## How registration works

The library does not register `PamsJwtTokenCustomizer` as a normal unconditional bean. Instead, `SecurityConfig` uses a
`BeanFactoryPostProcessor` that only registers the default customizer when no other
`OAuth2TokenCustomizer<JwtEncodingContext>` bean already exists.

That means a custom bean replaces the default mapping automatically.

## Packaging caveat

If your customizer lives in a package scanned by your Spring Boot application, no extra registration is needed.

If it lives outside the component-scan path, you must import its configuration explicitly, for example via
`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.

This is not a special rule of the mock server itself; it is the normal Spring Boot requirement for making an
auto-configuration visible outside the application's scan base package.

## Built-in mappers

The library exposes two reusable base implementations:

- `PamsJwtTokenCustomizer` for jEAP / PAMS-style claims such as `context`, `userroles`, `bproles`, `ext_id`,
  `admin_dir_uid`, and `login`
- `EiamJwtAccessTokenCustomizer` for eIAM-style claims such as `role`, `userExtId`, `email`, and `language`

`UserInfoMapper` also copies the custom claims defined by the library claim enum into the OIDC userinfo response.

## Related topics

- [Configuration](configuration.md)
- [Architecture](architecture.md)
- [Upgrading](upgrading.md)
