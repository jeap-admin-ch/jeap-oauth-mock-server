package ch.admin.bit.jeap.oauth.mock.server.config;

import lombok.Data;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import jakarta.validation.constraints.NotEmpty;
import java.time.Duration;
import java.util.*;

@Data
public class ClientData {
    private static final String USERROLES = "userroles";
    private static final String BPROLES = "bproles";
    private static final String AUDIENCE = "audience";
    private static final String SUBJECT = "subject";
    private static final String CONTEXT = "context";
    private static final String BPROLES_SCOPE_ENABLED = "bproles-scope-enabled";
    private static final String BPROLES_SCOPE = "bproles:*";

    private static final Duration DEFAULT_TOKEN_VALIDITY = Duration.ofHours(1);

    @NotEmpty
    private String clientId;
    private String clientSecret = null;
    private List<String> registeredRedirectUri = List.of();

    private Long accessTokenValiditySeconds;
    private Long refreshTokenValiditySeconds;

    private AuthContext context = null;
    private String subject = null;
    private List<String> audience = null;
    private List<String> userroles = null;
    private Map<String, List<String>> bproles = null;
    private List<String> scope = List.of();
    private boolean bprolesScopeEnabled = false;

    public RegisteredClient toRegisteredClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(clientSecret == null ? null : clientSecret)
                .clientAuthenticationMethods(s -> s.addAll(getAuthenticationMethods()))
                .authorizationGrantTypes(s -> s.addAll(getAuthorizationGrantTypes()))
                .scopes(c -> {
                    c.addAll(scope);
                    // Default OIDC scopes are always allowed
                    c.add(OidcScopes.ADDRESS);
                    c.add(OidcScopes.PHONE);
                    c.add(OidcScopes.PROFILE);
                    c.add(OidcScopes.OPENID);
                    c.add(OidcScopes.EMAIL);
                    // Add dynamic scope 'bproles' if enabled (and not yet configured)
                    if (bprolesScopeEnabled && !scope.contains(BPROLES_SCOPE)) {
                        c.add(BPROLES_SCOPE);
                    }
                })
                .clientSettings(createClientSettings())
                .redirectUris(uris -> uris.addAll(registeredRedirectUri))
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(accessTokenValiditySeconds != null ? Duration.ofSeconds(accessTokenValiditySeconds) : DEFAULT_TOKEN_VALIDITY)
                        .refreshTokenTimeToLive(refreshTokenValiditySeconds != null ? Duration.ofSeconds(refreshTokenValiditySeconds) : DEFAULT_TOKEN_VALIDITY)
                        .build())
                .build();
    }

    private ClientSettings createClientSettings() {
        ClientSettings.Builder builder = ClientSettings.builder().requireAuthorizationConsent(false);
        if (context != null){
            builder.setting(CONTEXT, context.name());
        }
        if (userroles != null) {
            builder.setting(USERROLES, userroles);
        }
        if (bproles != null) {
            builder.setting(BPROLES, bproles);
        }
        if (audience != null) {
            builder.setting(AUDIENCE, audience);
        }
        if (subject != null) {
            builder.setting(SUBJECT, subject);
        }
        builder.setting(BPROLES_SCOPE_ENABLED, bprolesScopeEnabled);
        return builder.build();
    }

    private Set<AuthorizationGrantType> getAuthorizationGrantTypes() {
        if (context != null) {
            return Set.of(context.grantType());
        } else {
            Set<AuthorizationGrantType> authorizationGrantTypes = new HashSet<>();
            authorizationGrantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);

            if (!registeredRedirectUri.isEmpty()) {
                authorizationGrantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
            }
            return authorizationGrantTypes;
        }
    }

    private Set<ClientAuthenticationMethod> getAuthenticationMethods(){
        if (context != null) {
            return context.clientAuthenticationMethods();
        } else {
            return  Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST, ClientAuthenticationMethod.NONE);
        }
    }

    public static String getContext(RegisteredClient registeredClient) {
        return (String) registeredClient.getClientSettings().getSettings().get(CONTEXT);
    }

    public static String getSubject(RegisteredClient client) {
        return (String) client.getClientSettings().getSettings().get(SUBJECT);
    }

    @SuppressWarnings("unchecked")
    public static List<String> getAudience(RegisteredClient client) {
        return (List<String>) client.getClientSettings().getSettings().get(AUDIENCE);
    }

    @SuppressWarnings("unchecked")
    public static List<String> getUserRolesForClient(RegisteredClient client) {
        return (List<String>) client.getClientSettings().getSettings().get(USERROLES);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, List<String>> getBusinessPartnerRolesForClient(RegisteredClient client) {
        return (Map<String, List<String>>) client.getClientSettings().getSettings().get(BPROLES);
    }

    public static boolean isBprolesScopeEnabled(RegisteredClient client) {
        return (Boolean) client.getClientSettings().getSettings().get(BPROLES_SCOPE_ENABLED);
    }

}
