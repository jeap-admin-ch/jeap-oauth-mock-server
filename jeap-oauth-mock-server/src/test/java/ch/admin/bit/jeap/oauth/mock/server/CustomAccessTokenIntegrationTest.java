package ch.admin.bit.jeap.oauth.mock.server;

import ch.admin.bit.jeap.oauth.mock.server.OAuth2AccessTokenTestTemplate.TestClientConfig;
import ch.admin.bit.jeap.oauth.mock.server.TokenCustomizerConfiguration.TestClaimCustomizer;
import ch.admin.bit.jeap.oauth.mock.server.token.Claims;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.context.ActiveProfiles;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"client-credentials-test"})
@Import(TokenCustomizerConfiguration.class)
class CustomAccessTokenIntegrationTest {

    @LocalServerPort
    int localServerPort;

    @Test
    void accessTokenRequest_shouldReturnTokenForClientCredentialsFlow_withCustomClaims() throws ParseException {
        // given
        TestClientConfig clientConfig = TestClientConfig.builder()
                .clientId("test-client")
                .scope("testscope")
                .build();
        OAuth2AccessTokenTestTemplate tokenTestTemplate = new OAuth2AccessTokenTestTemplate(clientConfig, localServerPort);

        // when: getting access token using client credentials flow
        OAuth2AccessToken accessToken = tokenTestTemplate.requestAccessToken();

        // then: expect the access token to contain only the claims set in the customizer in TokenCustomizerConfiguration
        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(accessToken);
        assertEquals(TestClaimCustomizer.ACCESS_TOKEN_VALUE, jwtClaimsSet.getStringClaim(TestClaimCustomizer.TEST_CLAIM));
        assertNull(jwtClaimsSet.getStringClaim(Claims.EXT_ID.claim()));
    }
}
