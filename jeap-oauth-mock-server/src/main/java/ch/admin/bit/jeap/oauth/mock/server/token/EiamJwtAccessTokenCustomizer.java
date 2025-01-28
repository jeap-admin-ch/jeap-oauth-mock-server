package ch.admin.bit.jeap.oauth.mock.server.token;


import ch.admin.bit.jeap.oauth.mock.server.config.ClientData;
import ch.admin.bit.jeap.oauth.mock.server.config.OAuthMockData.UserData;
import ch.admin.bit.jeap.oauth.mock.server.login.CustomLoginDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.springframework.util.StringUtils.hasText;

/**
 * Access token customizer for simulating access tokens as issued by eIAM.
 */
@Slf4j
public class EiamJwtAccessTokenCustomizer extends AbstractJwtTokenCustomizer {

    @Override
    protected void customizeAccessToken(JwtEncodingContext context, Map<String, Object> claims) {
        String clientId = getClientIdFromSecurityContext();
        setClaims(clientId, claims, context.getPrincipal());
        log.info("Issued access token with claims " + claims);
    }

    @Override
    protected void customizeIdToken(JwtEncodingContext context, Map<String, Object> claims) {
        String clientId = getClientIdFromSecurityContext();
        setClaims(clientId, claims, context.getPrincipal());
        updateClaimsForIdToken(clientId, claims);
        log.info("Issued id token with claims " + claims);
    }

    private void setClaims(String clientId, Map<String, Object> claims, Authentication userAuthentication) {
        RegisteredClient clientData = requireClient(clientId);
        UserData userData = getUserDataIfInUserContext(userAuthentication);

        addSubjectClaim(clientData, userData, claims);
        addUserClaims(userData, claims);
        addAdditionalUserClaims(userData, claims);
        addRoleClaim(userData, clientData, claims);
        addAudienceClaim(clientData, claims);
    }

    private void addSubjectClaim(RegisteredClient client, UserData userData, Map<String, Object> claims) {
        String subject = subjectOrUuid(client, userData);
        claims.put(StandardClaimNames.SUB, subject);
    }

    private void addAudienceClaim(RegisteredClient client, Map<String, Object> additionalInfo) {
        List<String> audience = ClientData.getAudience(client);
        if (audience != null) {
            additionalInfo.put(IdTokenClaimNames.AUD, audience);
        } else {
            additionalInfo.remove(IdTokenClaimNames.AUD);
        }
    }

    private void addRoleClaim(UserData user, RegisteredClient client, Map<String, Object> claims) {
        // Use the roles defined on the user if provided, else use the roles defined on the client.
        // eIAM only provides simple roles (userroles), i.e. no business partner specific roles (bproles)
        List<String> roles = (user != null ? user.getUserroles() : ClientData.getUserRolesForClient(client));
        if (roles != null) {
            claims.put(EiamClaims.ROLE.claim(), roles);
        }
    }

    private void addUserClaims(UserData user, Map<String, Object> claims) {
        if (user != null) {
            claims.put(StandardClaimNames.NAME, user.getName());
            claims.put(StandardClaimNames.GIVEN_NAME, user.getGivenName());
            claims.put(StandardClaimNames.FAMILY_NAME, user.getFamilyName());
            claims.put(EiamClaims.LANGUAGE.claim(), user.getLocale().toLowerCase());
            claims.put(StandardClaimNames.PREFERRED_USERNAME, user.getPreferredUsername());
            claims.put(EiamClaims.USER_EXT_ID.claim(), user.getExtId());
            claims.put(EiamClaims.EMAIL.claim(), user.getEmail());
        }
    }

    private void updateClaimsForIdToken(String clientId, Map<String, Object> claims) {
        claims.remove(OidcClientMetadataClaimNames.SCOPE);
        // Audience must be set to the clientID for the ID token
        claims.put(IdTokenClaimNames.AUD, clientId);
    }

    private static String subjectOrUuid(RegisteredClient client, UserData userData) {
        if (userData != null && (hasText(userData.getSubject()) || hasText(userData.getPreferredUsername()))) {
            return hasText(userData.getPreferredUsername()) ? userData.getPreferredUsername() : userData.getSubject();
        } else {
            String subject = ClientData.getSubject(client);
            if (hasText(subject)) {
                return subject;
            }
        }
        return UUID.randomUUID().toString();
    }

    private UserData getUserDataIfInUserContext(Authentication userAuthentication) {
        if (userAuthentication == null || !(userAuthentication.getPrincipal() instanceof User user)) {
            return null;
        }

        CustomLoginDetails customLoginDetails = (CustomLoginDetails) userAuthentication.getDetails();
        UserData userDataDefaultsFromConfig = requireUser(user.getUsername());
        return customLoginDetails.toUserDataWithDefaults(userDataDefaultsFromConfig);
    }

    private enum EiamClaims {
        ROLE("role"),
        USER_EXT_ID("userExtId"),
        EMAIL("email"),
        LANGUAGE("language");

        private final String claim;

        EiamClaims(String claim) {
            this.claim = claim;
        }

        public String claim() {
            return claim;
        }
    }

}