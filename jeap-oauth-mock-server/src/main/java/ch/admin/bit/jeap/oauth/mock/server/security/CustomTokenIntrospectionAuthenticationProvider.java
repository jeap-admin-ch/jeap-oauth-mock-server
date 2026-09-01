package ch.admin.bit.jeap.oauth.mock.server.security;

import ch.admin.bit.jeap.oauth.mock.server.config.ClientData;
import ch.admin.bit.jeap.oauth.mock.server.config.IntrospectionEndpointAudienceCheck;
import ch.admin.bit.jeap.oauth.mock.server.config.MockServerConfig;
import ch.admin.bit.jeap.oauth.mock.server.config.OAuthMockData;
import ch.admin.bit.jeap.oauth.mock.server.login.CustomLoginDetails;
import ch.admin.bit.jeap.oauth.mock.server.token.Claims;
import ch.admin.bit.jeap.oauth.mock.server.token.PamsJwtTokenCustomizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class CustomTokenIntrospectionAuthenticationProvider implements AuthenticationProvider {

    private static final String CLAIM_ACTIVE = "active";
    private final OAuth2AuthorizationService authorizationService;
    private final JwtDecoder jwtDecoder;
    private final OAuthMockData oAuthMockData;
    private final MockServerConfig mockServerConfig;

    @Override
    public Authentication authenticate(@NonNull Authentication authentication) throws AuthenticationException {
        OAuth2TokenIntrospectionAuthenticationToken introspectionAuth = (OAuth2TokenIntrospectionAuthenticationToken) authentication;

        String tokenValue = introspectionAuth.getToken();

        OAuth2Authorization authorization = authorizationService.findByToken(tokenValue, null);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }

        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
        if (accessToken == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }

        OAuth2Token token = accessToken.getToken();

        Instant expiresAt = token.getExpiresAt();
        if (expiresAt == null || expiresAt.isBefore(Instant.now())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }

        // Add all claims from token
        Map<String, Object> claims = new LinkedHashMap<>(jwtDecoder.decode(tokenValue).getClaims());

        boolean isActive = checkAudience(introspectionAuth, claims);

        if (isActive) {
            claims.put(CLAIM_ACTIVE, true);
            if (claims.containsKey(Claims.ROLES_PRUNED_CHARS_CLAIM_NAME.claim())) {
                claims.remove(Claims.ROLES_PRUNED_CHARS_CLAIM_NAME.claim());
                UsernamePasswordAuthenticationToken principal = authorization.getAttribute("java.security.Principal");

                // AuthorizationCode Flow
                if (principal != null && principal.getDetails() != null) {
                    CustomLoginDetails details = (CustomLoginDetails) principal.getDetails();
                    claims.put(Claims.USERROLES.claim(), details.getUserRoles());
                    claims.put(Claims.BPROLES.claim(), getBpRolesMap(details.getBpRoles()));
                }

                // Client Credentials
                else {
                    RegisteredClient client = oAuthMockData.clientsById().get(authorization.getPrincipalName());
                    if (ClientData.getUserRolesForClient(client) != null) {
                        claims.put(Claims.USERROLES.claim(), ClientData.getUserRolesForClient(client));
                    }

                    if (ClientData.getBusinessPartnerRolesForClient(client) != null) {
                        claims.put(Claims.BPROLES.claim(), ClientData.getBusinessPartnerRolesForClient(client));
                        PamsJwtTokenCustomizer.applyBprolesScope(client, claims);
                    }
                }
            }

            log.debug("Added userRoles to token response: {}", claims.get(Claims.USERROLES.claim()));
            log.debug("Added bpRoles to token response: {}", claims.get(Claims.BPROLES.claim()));

        } else {
            claims.clear();
            claims.put(CLAIM_ACTIVE, false);
        }
        return new OAuth2TokenIntrospectionAuthenticationToken(tokenValue, introspectionAuth, OAuth2TokenIntrospection.builder().claims(cl -> cl.putAll(claims)).build());
    }

    private boolean checkAudience(OAuth2TokenIntrospectionAuthenticationToken introspectionAuth, Map<String, Object> claims) {
        IntrospectionEndpointAudienceCheck audienceCheck = mockServerConfig.getIntrospectionEndpointAudienceCheck();
        boolean warnMode = audienceCheck == IntrospectionEndpointAudienceCheck.WARN;
        boolean onMode = audienceCheck == IntrospectionEndpointAudienceCheck.ON;

        String clientId = getClientIdFromPrincipal(introspectionAuth);
        if (clientId == null) {
            logClientIdMissing(onMode);
            return warnMode;
        }

        IntrospectionEndpointAudienceCheck introspectionModeFromClient = getIntrospectionModeFromClient(clientId);
        if (introspectionModeFromClient != null) {
            warnMode = introspectionModeFromClient == IntrospectionEndpointAudienceCheck.WARN;
            onMode = introspectionModeFromClient == IntrospectionEndpointAudienceCheck.ON;
        }

        if (!onMode && !warnMode) {
            return true;
        }

        if (!getAudienceClaim(claims).contains(clientId)) {
            logAudienceMissing(onMode, clientId);
            return warnMode;
        }

        return true;
    }

    private void logClientIdMissing(boolean onMode) {
        if (onMode) {
            log.error("ClientId not found in Principal");
            return;
        }
        log.warn("ClientId not found in Principal");
    }

    private void logAudienceMissing(boolean onMode, String clientId) {
        if (onMode) {
            log.error("ClientId '{}' not found in audience claim", clientId);
            return;
        }
        log.warn("ClientId '{}' not found in audience claim", clientId);
    }

    private static Map<String, List<String>> getBpRolesMap(List<String> bpRoles) {
        bpRoles.remove("");
        Map<String, List<String>> bpRolesMap = new LinkedHashMap<>();
        for (String bpRole : bpRoles) {
            if (bpRole.isEmpty()) continue;
            String[] parts = bpRole.split(":", 2);
            if (parts.length == 2) {
                bpRolesMap.computeIfAbsent(parts[0], _ -> new java.util.ArrayList<>()).add(parts[1]);
                Collections.sort(bpRolesMap.get(parts[0]));
            }
        }
        return bpRolesMap;
    }

    @Override
    public boolean supports(@NonNull Class<?> authentication) {
        return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private String getClientIdFromPrincipal(OAuth2TokenIntrospectionAuthenticationToken introspectionAuth) {
        if (introspectionAuth.getPrincipal() instanceof OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken) {
            RegisteredClient registeredClient = oAuth2ClientAuthenticationToken.getRegisteredClient();
            if (registeredClient != null) {
                return registeredClient.getClientId();
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private List<String> getAudienceClaim(Map<String, Object> claims) {
        if (claims.containsKey(IdTokenClaimNames.AUD)) {
            return (List<String>) claims.get(IdTokenClaimNames.AUD);
        }
        return List.of();
    }

    private IntrospectionEndpointAudienceCheck getIntrospectionModeFromClient(String clientId) {
        Object setting = oAuthMockData.clientsById().get(clientId).getClientSettings().getSetting(ClientData.INTROSPECTION_ENDPOINT_AUDIENCE_CHECK);
        if (setting != null) {
            return (IntrospectionEndpointAudienceCheck) setting;
        }
        return null;
    }
}
