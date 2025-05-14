package ch.admin.bit.jeap.oauth.mock.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.response.Response;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"authorization-code-test-roles-pruning"})
class AuthorizationCodeFlowIntegrationRolesPruningTest extends AuthorizationCodeFlowTestBase {

    @Test
    @SneakyThrows
    void retrieveTokenUsingAuthCodeFlow_idToken_shouldContainsAllRoles() {
        String idToken = retrieveTokenUsingAuthCodeFlow("id_token");
        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(idToken);
        assertThat(jwtClaimsSet.getClaim("userroles")).isEqualTo(List.of("userrole"));
        assertThat(jwtClaimsSet.getClaim("bproles")).isEqualTo(Map.of("12345", List.of("bprole")));
        assertThat(jwtClaimsSet.getClaim("roles_pruned_chars")).isNull();
    }

    @Test
    @SneakyThrows
    @SuppressWarnings("unchecked")
    void introspectionEndpoint_shouldReturnFullToken() {
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token", Set.of("12345:bprole1", "12345:bprole2", "23456:bprole3"));

        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(accessToken);
        assertThat(jwtClaimsSet.getClaim("userroles")).isNull();
        assertThat(jwtClaimsSet.getClaim("bproles")).isNull();
        assertThat((Long) jwtClaimsSet.getClaim("roles_pruned_chars")).isGreaterThan(40);

        Response response = request()
                .auth().preemptive().basic("introspect-client", "secret")
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", accessToken)
                .when()
                .post("/oauth2/introspect")
                .then()
                .statusCode(200)
                .extract()
                .response();

        assertThat(response.jsonPath().getBoolean("active")).isTrue();
        assertThat(response.jsonPath().getList("userroles")).isEqualTo(List.of("userrole"));
        assertThat(response.jsonPath().getMap("bproles")).isEqualTo(Map.of("12345", List.of("bprole1", "bprole2"), "23456", List.of("bprole3")));
        assertThat(response.jsonPath().getList("roles_pruned_chars")).isNull();

        Map<String, Object> tokenMap = new ObjectMapper().readValue(SignedJWT.parse(accessToken).getParsedParts()[1].decodeToString(), Map.class);
        tokenMap.remove("roles_pruned_chars");

        tokenMap.forEach((key, expected) ->
                {
                    Object actual = response.jsonPath().get(key);
                    if (key.equals("scope")) {
                        assertEquals(String.join(" ", (List<String>) expected), actual);
                    } else if (key.equals("aud")) {
                        assertEquals(expected, ((List<String>) actual).getFirst());
                    } else {
                        assertEquals(expected, actual);
                    }
                }
        );
    }

}
