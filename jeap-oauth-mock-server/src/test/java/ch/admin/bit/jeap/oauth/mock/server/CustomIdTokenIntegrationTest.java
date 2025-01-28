package ch.admin.bit.jeap.oauth.mock.server;

import ch.admin.bit.jeap.oauth.mock.server.TokenCustomizerConfiguration.TestClaimCustomizer;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"authorization-code-test"})
@Import(TokenCustomizerConfiguration.class)
class CustomIdTokenIntegrationTest extends AuthorizationCodeFlowTestBase {

    @Test
    void tokenRequest_shouldReturnIDToken() throws ParseException {
        String idToken = retrieveTokenUsingAuthCodeFlow("id_token");

        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(idToken);
        assertEquals(TestClaimCustomizer.ID_TOKEN_VALUE, jwtClaimsSet.getStringClaim(TestClaimCustomizer.TEST_CLAIM));
    }

}
