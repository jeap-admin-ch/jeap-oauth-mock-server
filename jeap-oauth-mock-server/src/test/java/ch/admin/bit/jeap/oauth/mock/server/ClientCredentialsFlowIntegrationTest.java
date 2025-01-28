package ch.admin.bit.jeap.oauth.mock.server;

import ch.admin.bit.jeap.oauth.mock.server.OAuth2AccessTokenTestTemplate.TestClientConfig;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.context.ActiveProfiles;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"client-credentials-test"})
class ClientCredentialsFlowIntegrationTest {

    @LocalServerPort
    int localServerPort;

    @Test
    void accessTokenRequest_shouldReturnTokenForClientCredentialsFlow() throws ParseException {
        // given
        TestClientConfig clientConfig = TestClientConfig.builder()
                .clientId("test-client")
                .scope("testscope")
                .build();
        OAuth2AccessTokenTestTemplate tokenTestTemplate = new OAuth2AccessTokenTestTemplate(clientConfig, localServerPort);

        // when
        OAuth2AccessToken accessToken = tokenTestTemplate.requestAccessToken();

        // then (see application-client-credentials-test.yml for mock data configuration)
        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(accessToken);
        Map<String, Object> bpRoles = jwtClaimsSet.getJSONObjectClaim("bproles");
        List<String> userRoles = jwtClaimsSet.getStringListClaim("userroles");
        List<String> audience = jwtClaimsSet.getAudience();
        String subject = jwtClaimsSet.getSubject();
        String issuer = jwtClaimsSet.getIssuer();

        assertNotNull(bpRoles);
        assertEquals(singletonList("12345-testrole"), bpRoles.get("12345"));
        assertEquals(singletonList("testrole"), userRoles);
        assertEquals(singletonList("test-audience"), audience);
        assertEquals("mysubject", subject);
        assertEquals("http://localhost:8180", issuer);
    }

    @Test
    void accessTokenRequestScopedToOneBusinessPartner_shouldReturnTokenWithJustBprolesForThisBusinessPartner() throws ParseException {
        // given a token request scoped to business partner 1
        TestClientConfig clientConfig1 = TestClientConfig.builder()
                .clientId("test-client-bproles-scoped")
                .scope("openid")
                .scope("bproles:1")
                .build();
        OAuth2AccessTokenTestTemplate tokenTestTemplate1 = new OAuth2AccessTokenTestTemplate(clientConfig1, localServerPort);

        // when
        OAuth2AccessToken accessToken1 = tokenTestTemplate1.requestAccessToken();

        // then token only contains bproles for business partner 1 (see application-client-credentials-test.yml for mock data configuration)
        JWTClaimsSet jwtClaimsSet1 = TestTokenParser.parseJwtClaims(accessToken1);
        Map<String, Object> bpRoles1 = jwtClaimsSet1.getJSONObjectClaim("bproles");
        assertNotNull(bpRoles1);
        assertEquals(1, bpRoles1.size());
        assertEquals(singletonList("bprolea"), bpRoles1.get("1"));

        // given a token request scoped to business partner 2
        TestClientConfig clientConfig2 = TestClientConfig.builder()
                .clientId("test-client-bproles-scoped")
                .scope("openid")
                .scope("bproles:2")
                .build();
        OAuth2AccessTokenTestTemplate tokenTestTemplate2 = new OAuth2AccessTokenTestTemplate(clientConfig2, localServerPort);

        // when
        OAuth2AccessToken accessToken2 = tokenTestTemplate2.requestAccessToken();

        // then token only contains bproles for business partner 2 (see application-client-credentials-test.yml for mock data configuration)
        JWTClaimsSet jwtClaimsSet2 = TestTokenParser.parseJwtClaims(accessToken2);
        Map<String, Object> bpRoles2 = jwtClaimsSet2.getJSONObjectClaim("bproles");
        assertNotNull(bpRoles2);
        assertEquals(1, bpRoles2.size());
        assertEquals(singletonList("bproleb"), bpRoles2.get("2"));
    }

    @Test
    void accessTokenRequestScopedToAllBusinessPartners_shouldReturnTokenWithBprolesForAllBusinessPartners() throws ParseException {
        // given a token request scoped to all business partners
        TestClientConfig clientConfig = TestClientConfig.builder()
                .clientId("test-client-bproles-scoped")
                .scope("openid")
                .scope("bproles:*")
                .build();
        OAuth2AccessTokenTestTemplate tokenTestTemplate = new OAuth2AccessTokenTestTemplate(clientConfig, localServerPort);

        // when
        OAuth2AccessToken accessToken = tokenTestTemplate.requestAccessToken();

        // then token contains all bproles (see application-client-credentials-test.yml for mock data configuration)
        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(accessToken);
        Map<String, Object> bpRoles = jwtClaimsSet.getJSONObjectClaim("bproles");
        assertNotNull(bpRoles);
        assertEquals(2, bpRoles.size());
        assertEquals(singletonList("bprolea"), bpRoles.get("1"));
        assertEquals(singletonList("bproleb"), bpRoles.get("2"));
    }

    @Test
    void accessTokenRequestScopedToNoBusinessPartner_shouldReturnTokenWithoutBproles() throws ParseException {
        // given a token request not scoped to a business partner
        TestClientConfig clientConfig = TestClientConfig.builder()
                .clientId("test-client-bproles-scoped")
                .scope("openid")
                .build();
        OAuth2AccessTokenTestTemplate tokenTestTemplate = new OAuth2AccessTokenTestTemplate(clientConfig, localServerPort);

        // when
        OAuth2AccessToken accessToken = tokenTestTemplate.requestAccessToken();

        // then the token does not contain bproles (see application-client-credentials-test.yml for mock data configuration)
        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(accessToken);
        Map<String, Object> bpRoles = jwtClaimsSet.getJSONObjectClaim("bproles");
        assertNull(bpRoles);
    }

    @Test
    void accessTokenRequest_shouldReturnTokenForClientCredentialsFlowWithoutScope() throws ParseException {
        // given
        TestClientConfig clientConfig = TestClientConfig.builder()
                .clientId("noscope-client")
                .build();
        OAuth2AccessTokenTestTemplate tokenTestTemplate = new OAuth2AccessTokenTestTemplate(clientConfig, localServerPort);

        // when
        OAuth2AccessToken accessToken = tokenTestTemplate.requestAccessToken();

        // then (see application-client-credentials-test.yml for mock data configuration)
        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(accessToken);
        assertTrue(accessToken.getScopes().isEmpty());
        assertNull(jwtClaimsSet.getStringListClaim("aud"));
        assertNull(jwtClaimsSet.getClaim("bproles"));
        assertNull(jwtClaimsSet.getClaim("userroles"));
    }

}
