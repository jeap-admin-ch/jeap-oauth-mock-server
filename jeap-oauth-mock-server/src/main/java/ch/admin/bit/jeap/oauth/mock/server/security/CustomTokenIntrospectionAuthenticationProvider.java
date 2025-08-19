package ch.admin.bit.jeap.oauth.mock.server.security;

import ch.admin.bit.jeap.oauth.mock.server.config.ClientData;
import ch.admin.bit.jeap.oauth.mock.server.config.OAuthMockData;
import ch.admin.bit.jeap.oauth.mock.server.login.CustomLoginDetails;
import ch.admin.bit.jeap.oauth.mock.server.token.Claims;
import ch.admin.bit.jeap.oauth.mock.server.token.PamsJwtTokenCustomizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
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

    private final OAuth2AuthorizationService authorizationService;
    private final JwtDecoder jwtDecoder;
    private final OAuthMockData oAuthMockData;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2TokenIntrospectionAuthenticationToken introspectionAuth = (OAuth2TokenIntrospectionAuthenticationToken) authentication;

        String tokenValue = introspectionAuth.getToken();

        OAuth2Authorization authorization = authorizationService.findByToken(tokenValue, null);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }

        OAuth2Token token = authorization.getAccessToken().getToken();
        if (token == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }

        Instant expiresAt = token.getExpiresAt();
        if (expiresAt == null || expiresAt.isBefore(Instant.now())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }

        // Add all claims from token
        Map<String, Object> claims = new LinkedHashMap<>(jwtDecoder.decode(tokenValue).getClaims());
        claims.put("active", true);

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
        return new OAuth2TokenIntrospectionAuthenticationToken(tokenValue, introspectionAuth, OAuth2TokenIntrospection.builder().claims(cl -> cl.putAll(claims)).build());
    }

    private static Map<String, List<String>> getBpRolesMap(List<String> bpRoles) {
        bpRoles.remove("");
        Map<String, List<String>> bpRolesMap = new LinkedHashMap<>();
        for (String bpRole : bpRoles) {
            if (bpRole.isEmpty()) continue;
            String[] parts = bpRole.split(":", 2);
            if (parts.length == 2) {
                bpRolesMap.computeIfAbsent(parts[0], k -> new java.util.ArrayList<>()).add(parts[1]);
                Collections.sort(bpRolesMap.get(parts[0]));
            }
        }
        return bpRolesMap;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
