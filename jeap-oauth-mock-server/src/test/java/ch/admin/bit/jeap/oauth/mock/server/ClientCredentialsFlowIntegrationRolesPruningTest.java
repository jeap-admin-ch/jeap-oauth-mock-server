package ch.admin.bit.jeap.oauth.mock.server;

import ch.admin.bit.jeap.oauth.mock.server.OAuth2AccessTokenTestTemplate.TestClientConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.RestAssured;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.context.ActiveProfiles;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static io.restassured.config.RedirectConfig.redirectConfig;
import static io.restassured.config.RestAssuredConfig.newConfig;
import static io.restassured.config.SessionConfig.sessionConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"client-credentials-test-roles-pruning"})
class ClientCredentialsFlowIntegrationRolesPruningTest {

    @LocalServerPort
    int localServerPort;

    private CookieFilter cookieFilter;

    @BeforeEach
    void setUp() {
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
        cookieFilter = new CookieFilter();
    }

    @Test
    @SneakyThrows
    @SuppressWarnings("unchecked")
    void accessTokenRequest_shouldReturnTokenForClientCredentialsFlow() {
        // given
        TestClientConfig clientConfig = TestClientConfig.builder()
                .clientId("test-client")
                .scope("testscope")
                .build();
        OAuth2AccessTokenTestTemplate tokenTestTemplate = new OAuth2AccessTokenTestTemplate(clientConfig, localServerPort);

        // when
        OAuth2AccessToken accessToken = tokenTestTemplate.requestAccessToken();
        assertTokenIsPruned(accessToken);

        Response response = callIntrospectionEndpoint("test-client", accessToken);

        assertThat(response.jsonPath().getBoolean("active")).isTrue();
        assertThat(response.jsonPath().getList("userroles")).isEqualTo(List.of("testrole", "testrole2"));
        assertThat(response.jsonPath().getMap("bproles")).isEqualTo(Map.of("12345", List.of("bprole1","bprole2"), "23456", List.of("other-bprole")));
        assertThat(response.jsonPath().getList("roles_pruned_chars")).isNull();

        Map<String, Object> tokenMap = new ObjectMapper().readValue(SignedJWT.parse(accessToken.getTokenValue()).getParsedParts()[1].decodeToString(), Map.class);
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

    private static void assertTokenIsPruned(OAuth2AccessToken accessToken) throws ParseException {
        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(accessToken);
        assertThat(jwtClaimsSet.getClaim("userroles")).isNull();
        assertThat(jwtClaimsSet.getClaim("bproles")).isNull();
        assertThat((Long) jwtClaimsSet.getClaim("roles_pruned_chars")).isGreaterThan(40);
    }


    @Test
    void accessTokenRequestScopedToOneBusinessPartner_shouldReturnTokenWithJustBpRolesForThisBusinessPartner() throws ParseException {
        // given a token request scoped to business partner 1
        TestClientConfig clientConfig1 = TestClientConfig.builder()
                .clientId("test-client-bproles-scoped")
                .scope("openid")
                .scope("bproles:1")
                .build();

        // when
        OAuth2AccessToken accessToken1 = new OAuth2AccessTokenTestTemplate(clientConfig1, localServerPort).requestAccessToken();
        assertTokenIsPruned(accessToken1);

        Response response = callIntrospectionEndpoint("test-client-bproles-scoped", accessToken1);

        assertThat(response.jsonPath().getBoolean("active")).isTrue();
        assertThat(response.jsonPath().getList("userroles")).isEqualTo(List.of("testrole", "testrole2", "testrole3"));
        assertThat(response.jsonPath().getMap("bproles")).isEqualTo(Map.of("1", List.of("bprolea")));
        assertThat(response.jsonPath().getList("roles_pruned_chars")).isNull();


        // given a token request scoped to business partner 2
        TestClientConfig clientConfig2 = TestClientConfig.builder()
                .clientId("test-client-bproles-scoped")
                .scope("openid")
                .scope("bproles:2")
                .build();

        // when
        OAuth2AccessToken accessToken2 = new OAuth2AccessTokenTestTemplate(clientConfig2, localServerPort).requestAccessToken();
        assertTokenIsPruned(accessToken2);

        response = callIntrospectionEndpoint("test-client-bproles-scoped", accessToken2);

        assertThat(response.jsonPath().getBoolean("active")).isTrue();
        assertThat(response.jsonPath().getList("userroles")).isEqualTo(List.of("testrole", "testrole2", "testrole3"));
        assertThat(response.jsonPath().getMap("bproles")).isEqualTo(Map.of("2", List.of("bproleb")));
        assertThat(response.jsonPath().getList("roles_pruned_chars")).isNull();

    }

    @Test
    void accessTokenRequestScopedToAllBusinessPartners_shouldReturnTokenWithBpRolesForAllBusinessPartners() throws ParseException {
        // given a token request scoped to all business partners
        TestClientConfig clientConfig = TestClientConfig.builder()
                .clientId("test-client-bproles-scoped")
                .scope("openid")
                .scope("bproles:*")
                .build();

        // when
        OAuth2AccessToken accessToken = new OAuth2AccessTokenTestTemplate(clientConfig, localServerPort).requestAccessToken();
        assertTokenIsPruned(accessToken);

        Response response = callIntrospectionEndpoint("test-client-bproles-scoped", accessToken);

        assertThat(response.jsonPath().getBoolean("active")).isTrue();
        assertThat(response.jsonPath().getList("userroles")).isEqualTo(List.of("testrole", "testrole2", "testrole3"));
        assertThat(response.jsonPath().getMap("bproles")).isEqualTo(Map.of("1", List.of("bprolea"), "2", List.of("bproleb")));
        assertThat(response.jsonPath().getList("roles_pruned_chars")).isNull();

    }

    @Test
    void accessTokenRequestScopedToNoBusinessPartner_shouldReturnTokenWithoutBpRoles() throws ParseException {
        // given a token request not scoped to a business partner
        TestClientConfig clientConfig = TestClientConfig.builder()
                .clientId("test-client-bproles-scoped")
                .scope("openid")
                .build();

        // when
        OAuth2AccessToken accessToken = new OAuth2AccessTokenTestTemplate(clientConfig, localServerPort).requestAccessToken();
        assertTokenIsPruned(accessToken);

        Response response = callIntrospectionEndpoint("test-client-bproles-scoped", accessToken);

        assertThat(response.jsonPath().getBoolean("active")).isTrue();
        assertThat(response.jsonPath().getList("userroles")).isEqualTo(List.of("testrole", "testrole2", "testrole3"));
        assertThat(response.jsonPath().getMap("bproles")).isNull();
        assertThat(response.jsonPath().getList("roles_pruned_chars")).isNull();

    }

    private Response callIntrospectionEndpoint(String s, OAuth2AccessToken accessToken) {
        return request()
                .auth().preemptive().basic(s, "secret")
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", accessToken.getTokenValue())
                .when()
                .post("/oauth2/introspect")
                .then()
                .statusCode(200)
                .extract()
                .response();
    }

    protected RequestSpecification request() {
        return RestAssured.given()
                .port(localServerPort)
                .config(newConfig()
                        .redirect(redirectConfig().followRedirects(false))
                        .sessionConfig(sessionConfig()))
                .filter(cookieFilter)
                .log().uri();
    }

}
