package ch.admin.bit.jeap.oauth.mock.server.token;

import ch.admin.bit.jeap.oauth.mock.server.config.ClientData;
import ch.admin.bit.jeap.oauth.mock.server.config.OAuthMockData.UserData;
import ch.admin.bit.jeap.oauth.mock.server.login.CustomLoginDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.*;

import static org.springframework.util.StringUtils.hasText;

/**
 * Adds PAMS role claims to Access Tokens.
 * Note: This is the default {@link OAuth2TokenCustomizer} implementation, which is active if no custom
 * {@link OAuth2TokenCustomizer} bean has been provided for the OAuth mock server instance.
 */
@Slf4j
public class PamsJwtAccessTokenCustomizer extends AbstractJwtTokenCustomizer {

    public enum Claims {
        CONTEXT("ctx"),
        USERROLES("userroles"),
        BPROLES("bproles"),
        EXT_ID("ext_id"),
        ADMIN_DIR_UID("admin_dir_uid"),
        LOGIN("login_level");

        private final String claim;

        Claims(String claim) {
            this.claim = claim;
        }

        public String claim() {
            return claim;
        }
    }

    @Override
    protected void customizeAccessToken(JwtEncodingContext context, Map<String, Object> claims) {
        String clientId = getClientIdFromSecurityContext();
        addPamsClaims(context, clientId, claims, context.getPrincipal());
    }

    @Override
    protected void customizeIdToken(JwtEncodingContext context, Map<String, Object> claims) {
        String clientId = getClientIdFromSecurityContext();
        addPamsClaims(context, clientId, claims, context.getPrincipal());
        updatePamsClaimsForIdToken(clientId, claims);
    }

    private void addPamsClaims(JwtEncodingContext context, String clientId, Map<String, Object> claims, Authentication userAuthentication) {
        RegisteredClient clientData = requireClient(clientId);

        addContextClaim(claims, clientData, context.getAuthorizationGrantType());
        addAudienceClaim(clientData, claims);
        addClientDefaultBpRoleClaim(clientData, claims);
        addClientDefaultUserrolesClaim(clientData, claims);

        UserData userData = getUserDataIfInUserContext(userAuthentication);
        addUserClaims(userData, claims);
        addBpRoleClaim(userData, claims);
        addUserrolesClaim(userData, claims);
        addSubjectClaim(clientData, userData, claims);
        addAdditionalUserClaims(userData, claims);

        applyBprolesScope(clientData, claims);

        log.info("Issued access token with claims " + claims);
    }

    private static void applyBprolesScope(RegisteredClient client, Map<String, Object> claims) {
        // Only apply bproles scope if enabled for the client
        if (ClientData.isBprolesScopeEnabled(client)) {
            Optional<BprolesScope> bprolesScope = getBprolesScope(claims);
            if (bprolesScope.isEmpty()) {
                // no bproles scope -> no bproles in token
                removeBprolesClaim(claims);
            } else {
                if (!bprolesScope.get().includesAllPartners()) {
                    // restrict the bproles to the specific business partner from the bproles scope
                    String businessPartner = bprolesScope.get().getBusinessPartner();
                    restrictBprolesClaimToBusinessPartner(claims, businessPartner);
                } else {
                    // do not filter the bproles when the bproles scope selects all business partners
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Optional<BprolesScope> getBprolesScope(Map<String, Object> claims) {
        Set<String> scopes = (Set<String>) claims.getOrDefault(OAuth2TokenIntrospectionClaimNames.SCOPE, Set.of());
        return scopes.stream().map(BprolesScope::from).filter(Objects::nonNull).findFirst();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, List<String>> getBproles(Map<String, Object> claims) {
        return (Map<String, List<String>>) claims.getOrDefault(Claims.BPROLES.claim(), Map.of());
    }

    private static void restrictBprolesClaimToBusinessPartner(Map<String, Object> claims, String businessPartner) {
        List<String> bprolesOfBusinessPartner = getBproles(claims).getOrDefault(businessPartner, List.of());
        if (!bprolesOfBusinessPartner.isEmpty()) {
            claims.put(Claims.BPROLES.claim(), Map.of(businessPartner, bprolesOfBusinessPartner));
        } else {
            removeBprolesClaim(claims);
        }
    }

    private static void removeBprolesClaim(Map<String, Object> claims) {
        claims.remove(Claims.BPROLES.claim());
    }

    private static void addContextClaim(Map<String, Object> claims, RegisteredClient client, AuthorizationGrantType grantType) {
        if (ClientData.getContext(client) != null) {
            claims.put(Claims.CONTEXT.claim(), ClientData.getContext(client));
        } else {
            claims.put(Claims.CONTEXT.claim(), grantType.equals(AuthorizationGrantType.AUTHORIZATION_CODE) ? "USER" : "SYS");
        }
    }

    private void addSubjectClaim(RegisteredClient client, UserData userData, Map<String, Object> additionalInfo) {
        String subject = subjectOrUuid(client, userData);
        additionalInfo.put(StandardClaimNames.SUB, subject);
    }

    private static String subjectOrUuid(RegisteredClient client, UserData userData) {
        if (userData != null && (hasText(userData.getSubject()) || hasText(userData.getPreferredUsername()))) {
            // If the user chose to set a PAMS id on the mock server login page it must be set as subject, too.
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

    private void addAudienceClaim(RegisteredClient client, Map<String, Object> additionalInfo) {
        List<String> audience = ClientData.getAudience(client);
        if (audience != null) {
            additionalInfo.put(IdTokenClaimNames.AUD, audience);
        } else {
            additionalInfo.remove(IdTokenClaimNames.AUD);
        }
    }

    private void addClientDefaultUserrolesClaim(RegisteredClient client, Map<String, Object> additionalInfo) {
        List<String> userroles = ClientData.getUserRolesForClient(client);
        if (userroles != null) {
            additionalInfo.put(Claims.USERROLES.claim(), userroles);
        }
    }

    private void addClientDefaultBpRoleClaim(RegisteredClient client, Map<String, Object> additionalInfo) {
        Map<String, List<String>> bproles = ClientData.getBusinessPartnerRolesForClient(client);
        if (bproles != null) {
            additionalInfo.put(Claims.BPROLES.claim(), bproles);
        }
    }

    private void addUserrolesClaim(UserData user, Map<String, Object> additionalInfo) {
        if (user != null) {
            List<String> userroles = user.getUserroles();
            additionalInfo.put(Claims.USERROLES.claim(), userroles);
        }
    }

    private void addBpRoleClaim(UserData user, Map<String, Object> additionalInfo) {
        if (user != null) {
            Map<String, List<String>> bproles = user.getBproles();
            additionalInfo.put(Claims.BPROLES.claim(), bproles);
        }
    }

    private void addUserClaims(UserData user, Map<String, Object> additionalInfo) {
        if (user != null) {
            additionalInfo.put(StandardClaimNames.NAME, user.getName());
            additionalInfo.put(StandardClaimNames.GIVEN_NAME, user.getGivenName());
            additionalInfo.put(StandardClaimNames.FAMILY_NAME, user.getFamilyName());
            additionalInfo.put(StandardClaimNames.LOCALE, user.getLocale());
            additionalInfo.put(StandardClaimNames.PREFERRED_USERNAME, user.getPreferredUsername());
            additionalInfo.put(Claims.EXT_ID.claim(), user.getExtId());
            additionalInfo.put(Claims.ADMIN_DIR_UID.claim(), user.getAdminDirUID());
            additionalInfo.put(Claims.LOGIN.claim(), user.getLoginLevel());
        }
    }

    private void updatePamsClaimsForIdToken(String clientId, Map<String, Object> claims) {
        claims.remove(OidcClientMetadataClaimNames.SCOPE);

        // Audience must be set to the clientID for the ID token
        claims.put(IdTokenClaimNames.AUD, clientId);
    }

}
