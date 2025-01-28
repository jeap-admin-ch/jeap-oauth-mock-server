package ch.admin.bit.jeap.oauth.mock.server;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.text.ParseException;
import java.time.ZonedDateTime;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"authorization-code-test-validity"})
class AuthorizationCodeFlowIntegrationValidityTest extends AuthorizationCodeFlowTestBase {

    @Test
    void tokenRequest_shouldReturnAccessTokenWithValidityFromConfigFile() throws ParseException {
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token");
        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(accessToken);
        assertTrue(jwtClaimsSet.getExpirationTime().toInstant().isAfter(ZonedDateTime.now().plusMinutes(115).toInstant()));
    }


}
