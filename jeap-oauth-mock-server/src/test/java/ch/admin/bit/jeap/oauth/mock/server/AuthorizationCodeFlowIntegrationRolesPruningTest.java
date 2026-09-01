package ch.admin.bit.jeap.oauth.mock.server;

import ch.admin.bit.jeap.oauth.mock.server.config.IntrospectionEndpointAudienceCheck;
import ch.admin.bit.jeap.oauth.mock.server.config.MockServerConfig;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.response.Response;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import tools.jackson.databind.ObjectMapper;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"authorization-code-test-roles-pruning"})
class AuthorizationCodeFlowIntegrationRolesPruningTest extends AuthorizationCodeFlowTestBase {

    @MockitoSpyBean
    private MockServerConfig mockServerConfig;

    @BeforeEach
    void setup() {
        doReturn("https://localhost").when(mockServerConfig).getBaseUrl();
    }

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
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token", "test-client", Set.of("12345:bprole1", "12345:bprole2", "23456:bprole3"));

        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(accessToken);
        assertThat(jwtClaimsSet.getClaim("userroles")).isNull();
        assertThat(jwtClaimsSet.getClaim("bproles")).isNull();
        assertThat((Long) jwtClaimsSet.getClaim("roles_pruned_chars")).isGreaterThan(40);

        Response response = doIntrospectRequest(accessToken);

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

    @Test
    @SneakyThrows
    void introspectionEndpointWithoutAudience_checkAudienceDefault_returnTokenIsActive() {
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token", "test-client-without-audience", Set.of("12345:bprole1", "12345:bprole2", "23456:bprole3"));
        Response response = doIntrospectRequest(accessToken);
        assertThat(response.jsonPath().getBoolean("active")).isTrue();
    }

    @Test
    @SneakyThrows
    void introspectionEndpointWithoutAudience_checkAudienceWarn_returnTokenIsActive() {
        when(mockServerConfig.getIntrospectionEndpointAudienceCheck()).thenReturn(IntrospectionEndpointAudienceCheck.WARN);
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token", "test-client-without-audience", Set.of("12345:bprole1", "12345:bprole2", "23456:bprole3"));
        Response response = doIntrospectRequest(accessToken);
        assertThat(response.jsonPath().getBoolean("active")).isTrue();
    }

    @Test
    @SneakyThrows
    void introspectionEndpointWithoutAudience_checkAudienceOn_returnTokenIsNotActive() {
        when(mockServerConfig.getIntrospectionEndpointAudienceCheck()).thenReturn(IntrospectionEndpointAudienceCheck.ON);
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token", "test-client-without-audience", Set.of("12345:bprole1", "12345:bprole2", "23456:bprole3"));
        Response response = doIntrospectRequest(accessToken);
        assertThat(response.jsonPath().getBoolean("active")).isFalse();
    }

    @Test
    @SneakyThrows
    void introspectionEndpointWithWrongAudience_checkAudienceOn_returnTokenIsNotActive() {
        when(mockServerConfig.getIntrospectionEndpointAudienceCheck()).thenReturn(IntrospectionEndpointAudienceCheck.ON);
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token", "test-client", Set.of("12345:bprole1", "12345:bprole2", "23456:bprole3"));
        Response response = doIntrospectRequest(accessToken);
        assertThat(response.jsonPath().getBoolean("active")).isFalse();
    }

    @Test
    @SneakyThrows
    void introspectionEndpointWithCorrectAudience_checkAudienceOn_returnTokenIsActive() {
        when(mockServerConfig.getIntrospectionEndpointAudienceCheck()).thenReturn(IntrospectionEndpointAudienceCheck.ON);
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token", "test-client-with-audience", Set.of("12345:bprole1", "12345:bprole2", "23456:bprole3"));
        Response response = doIntrospectRequest(accessToken);
        assertThat(response.jsonPath().getBoolean("active")).isTrue();
        assertThat(response.jsonPath().getMap("bproles")).isNotEmpty();
    }

    @Test
    @SneakyThrows
    void introspectionEndpointWithoutAudience_checkAudienceDefaultButConfiguredInClient_returnTokenIsNotActive() {
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token", "test-client-without-audience", Set.of("12345:bprole1", "12345:bprole2", "23456:bprole3"));
        Response response = doIntrospectRequest("introspect-client-with-on", accessToken);
        assertThat(response.jsonPath().getBoolean("active")).isFalse();
        assertThat(response.jsonPath().getList("userroles")).isNull();
        assertThat(response.jsonPath().getMap("bproles")).isNull();
    }

    private Response doIntrospectRequest(String accessToken) {
        return doIntrospectRequest("introspect-client", accessToken);
    }

    private Response doIntrospectRequest(String clientId, String accessToken) {
        return request()
                .auth().preemptive().basic(clientId, "secret")
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", accessToken)
                .when()
                .post("/oauth2/introspect")
                .then()
                .statusCode(200)
                .extract()
                .response();
    }

}
