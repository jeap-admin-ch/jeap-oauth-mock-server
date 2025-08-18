package ch.admin.bit.jeap.oauth.mock.server.token;

import ch.admin.bit.jeap.oauth.mock.server.config.OAuthMockData.UserData;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Map;
import java.util.Set;

@SuppressWarnings("SpringJavaAutowiredMembersInspection")
@Slf4j
public abstract class AbstractJwtTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private Map<String, RegisteredClient> clientsById;
    private Map<String, UserData> usersById;

    @Autowired
    public final void setClientsById(Map<String, RegisteredClient> clientsById) {
        this.clientsById = clientsById;
    }

    @Autowired
    public final void setUsersById(Map<String, UserData> usersById) {
        this.usersById = usersById;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        context.getClaims().claims(claims -> {
            if (isAccessToken(context)) {
                customizeAccessToken(context, claims);
            }
            if (isIdToken(context)) {
                // Scopes are available from the authorization context
                Set<String> scopes = context.getAuthorizedScopes();
                // add scopes into ID token claims as required for bpscoped clients
                if (scopes != null && !scopes.isEmpty()) {
                    claims.put("scope", scopes);
                }
                customizeIdToken(context, claims);
            }
        });
    }

    protected abstract void customizeAccessToken(JwtEncodingContext context, Map<String, Object> claims);

    protected abstract void customizeIdToken(JwtEncodingContext context, Map<String, Object> claims);

    protected static boolean isAccessToken(JwtEncodingContext context) {
        return context.getTokenType().getValue().equals(OAuth2TokenType.ACCESS_TOKEN.getValue());
    }

    protected static boolean isIdToken(JwtEncodingContext context) {
        return context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN);
    }

    /**
     * @return The {@link RegisteredClient} from the mock server's configuration for the given client ID
     * @throws OAuth2AuthenticationException if the client ID is not found in the mock server configuration
     */
    protected RegisteredClient requireClient(String clientId) {
        RegisteredClient registeredClient = clientsById.get(clientId);
        if (registeredClient == null) {
            throw unknownClientException(clientId);
        }
        return registeredClient;
    }

    /**
     * @return The {@link UserData} from the mock server's configuration for the given user name
     * @throws OAuth2AuthenticationException if a user with this name is not found in the mock server configuration
     */
    protected UserData requireUser(String name) {
        UserData userData = usersById.get(name);
        if (userData == null) {
            throw unknownUserException(name);
        }
        return userData;
    }

    /**
     * @return The client ID for which a token is issued
     */
    protected static String getClientIdFromSecurityContext() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof User user) {
            return user.getUsername();
        }
        return principal.toString();
    }

    protected void addAdditionalUserClaims(UserData userData, Map<String, Object> claims) {
        if (userData == null || userData.getAdditionalClaims() == null) {
            return; // nothing to set
        }
        for (Map.Entry<String, Object> entry : userData.getAdditionalClaims().entrySet()) {
            if (entry.getValue() != null) {
                claims.put(entry.getKey(), entry.getValue());
            }
        }
    }

    private static OAuth2AuthenticationException unknownClientException(String clientId) {
        String msg = "Unknown client: " + clientId;
        log.error(msg);
        return new OAuth2AuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT), msg);
    }

    private static OAuth2AuthenticationException unknownUserException(String username) {
        String msg = "Unknown user: " + username;
        log.error(msg);
        return new OAuth2AuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED), msg);
    }
}
