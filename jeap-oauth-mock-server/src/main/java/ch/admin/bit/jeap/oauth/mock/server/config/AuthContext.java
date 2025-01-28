package ch.admin.bit.jeap.oauth.mock.server.config;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.Set;

public enum AuthContext {
    // system-to-system context (client credentials flow)
    SYS(AuthorizationGrantType.CLIENT_CREDENTIALS, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST),
    // b2b context (client credentials flow)
    B2B(AuthorizationGrantType.CLIENT_CREDENTIALS, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST),
    // user context (authorization code flow / ClientAuthenticationMethod.CLIENT_SECRET_POST is required for Swagger)
    USER(AuthorizationGrantType.AUTHORIZATION_CODE, ClientAuthenticationMethod.NONE, ClientAuthenticationMethod.CLIENT_SECRET_POST);

    private final AuthorizationGrantType grantType;
    private final Set<ClientAuthenticationMethod> clientAuthenticationMethods;

    AuthContext(AuthorizationGrantType grantType, ClientAuthenticationMethod... clientAuthenticationMethods) {
        this.grantType = grantType;
        this.clientAuthenticationMethods = Set.of(clientAuthenticationMethods);
    }

    public AuthorizationGrantType grantType() {
        return grantType;
    }

    public Set<ClientAuthenticationMethod> clientAuthenticationMethods() {
        return clientAuthenticationMethods;
    }
}
