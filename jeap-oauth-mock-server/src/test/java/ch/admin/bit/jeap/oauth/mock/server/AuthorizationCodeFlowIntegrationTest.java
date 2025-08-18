package ch.admin.bit.jeap.oauth.mock.server;

import ch.admin.bit.jeap.oauth.mock.server.login.CustomLoginController;
import com.nimbusds.jwt.JWTClaimsSet;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.test.context.ActiveProfiles;

import java.text.ParseException;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"authorization-code-test"})
class AuthorizationCodeFlowIntegrationTest extends AuthorizationCodeFlowTestBase {

    @Test
    void tokenRequest_shouldReturnAccessToken() throws ParseException {
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token");

        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(accessToken);
        assertEquals(singletonList("example-resource"), jwtClaimsSet.getStringListClaim("aud"));
        assertTrue(jwtClaimsSet.getStringClaim("iss").startsWith("http://localhost:"));
        assertEquals("12345", jwtClaimsSet.getStringClaim("sub"));
        assertEquals("USER", jwtClaimsSet.getStringClaim("ctx"));
        assertEquals("Henriette", jwtClaimsSet.getStringClaim("given_name"));
        assertEquals("Muster", jwtClaimsSet.getStringClaim("family_name"));
        assertEquals("Henriette Muster", jwtClaimsSet.getStringClaim("name"));
        assertEquals("DE", jwtClaimsSet.getStringClaim("locale"));
        assertEquals("12345", jwtClaimsSet.getStringClaim("preferred_username"));
        assertEquals("56789", jwtClaimsSet.getStringClaim("ext_id"));
        assertEquals("U11111111", jwtClaimsSet.getStringClaim("admin_dir_uid"));
        assertEquals("S1+OK", jwtClaimsSet.getStringClaim("login_level"));

        assertEquals(singletonList("userrole"), jwtClaimsSet.getStringListClaim("userroles"));
        assertEquals(singletonList("bprole"), jwtClaimsSet.getJSONObjectClaim("bproles").get("12345"));

        assertTrue(jwtClaimsSet.getExpirationTime().toInstant().isAfter(ZonedDateTime.now().plusMinutes(50).toInstant()));
    }

    @Test
    void tokenRequestScopedForOneBusinessPartner_shouldReturnAccessTokenWithJustBprolesOfThisBusinessPartner() throws ParseException {
        // Fetch token for business partner 1
        String accessToken1 = retrieveTokenUsingAuthCodeFlow("access_token",
                "test-client-bpscoped", Set.of("bproles:1"), Set.of("1:userbprolea", "2:userbproleb"));

        JWTClaimsSet jwtClaimsSet1 = TestTokenParser.parseJwtClaims(accessToken1);
        assertEquals(1, jwtClaimsSet1.getJSONObjectClaim("bproles").size());
        assertEquals(singletonList("userbprolea"), jwtClaimsSet1.getJSONObjectClaim("bproles").get("1"));

        // Fetch token for business partner 2
        String accessToken2 = retrieveTokenUsingAuthCodeFlow("access_token",
                "test-client-bpscoped", Set.of("bproles:2"), Set.of("1:userbprolea", "2:userbproleb"));

        JWTClaimsSet jwtClaimsSet2 = TestTokenParser.parseJwtClaims(accessToken2);
        assertEquals(1, jwtClaimsSet2.getJSONObjectClaim("bproles").size());
        assertEquals(singletonList("userbproleb"), jwtClaimsSet2.getJSONObjectClaim("bproles").get("2"));
    }

    @Test
    void tokenRequestScopedForAllBusinessPartners_shouldReturnAccessTokenWithBprolesOfAllBusinessPartners() throws ParseException {
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token",
                "test-client-bpscoped", Set.of("bproles:*"), Set.of("1:userbprolea", "2:userbproleb"));

        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(accessToken);
        assertEquals(2, jwtClaimsSet.getJSONObjectClaim("bproles").size());
        assertEquals(singletonList("userbprolea"), jwtClaimsSet.getJSONObjectClaim("bproles").get("1"));
        assertEquals(singletonList("userbproleb"), jwtClaimsSet.getJSONObjectClaim("bproles").get("2"));
    }

    @Test
    void tokenRequestScopedForNoBusinessPartner_shouldReturnAccessTokenWithoutBproles() throws ParseException {
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token",
                "test-client-bpscoped", Set.of(), Set.of("1:userbprolea", "2:userbproleb"));

        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(accessToken);
        assertNull(jwtClaimsSet.getJSONObjectClaim("bproles"));
    }

    @Test
    void tokenRequest_shouldReturnIDToken() throws ParseException {
        String idToken = retrieveTokenUsingAuthCodeFlow("id_token");

        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(idToken);
        assertEquals("Henriette Muster", jwtClaimsSet.getStringClaim("name"));
        assertEquals("Henriette", jwtClaimsSet.getStringClaim("given_name"));
        assertEquals("Muster", jwtClaimsSet.getStringClaim("family_name"));
        assertEquals("DE", jwtClaimsSet.getStringClaim("locale"));
        assertEquals("12345", jwtClaimsSet.getStringClaim("preferred_username"));
        assertEquals("56789", jwtClaimsSet.getStringClaim("ext_id"));
        assertEquals("U11111111", jwtClaimsSet.getStringClaim("admin_dir_uid"));
        assertEquals("S1+OK", jwtClaimsSet.getStringClaim("login_level"));
        assertEquals("S1+OK", jwtClaimsSet.getStringClaim("login_level"));
        assertEquals("12345", jwtClaimsSet.getStringClaim("sub"));
        assertEquals(singletonList("test-client"), jwtClaimsSet.getStringListClaim("aud"));
        assertNotNull(jwtClaimsSet.getDateClaim("exp"));
        assertNotNull(jwtClaimsSet.getDateClaim("iat"));
        assertTrue(jwtClaimsSet.getStringClaim("iss").startsWith("http://localhost:"));
        assertEquals("ThisisaTest", jwtClaimsSet.getStringClaim("nonce"));
        assertEquals(singletonList("bprole"), jwtClaimsSet.getJSONObjectClaim("bproles").get("12345"));
        assertEquals("some-custom-claim1-value", jwtClaimsSet.getStringClaim("some-custom-claim1"));
        assertEquals("some-custom-claim2-value", jwtClaimsSet.getJSONObjectClaim("some-custom-claim2").get("0"));
        assertNull(jwtClaimsSet.getClaim("scope"));
    }

    @Test
    void tokenRequest_bpScopedClient_shouldReturnIDToken() throws ParseException {
        String idToken = retrieveTokenUsingAuthCodeFlow("id_token", "test-client-bpscoped", Set.of("bproles:*"), Set.of("12345:bprolea", "12346:bproleb"));

        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(idToken);
        assertEquals("Henriette Muster", jwtClaimsSet.getStringClaim("name"));
        assertEquals("Henriette", jwtClaimsSet.getStringClaim("given_name"));
        assertEquals("Muster", jwtClaimsSet.getStringClaim("family_name"));
        assertEquals("DE", jwtClaimsSet.getStringClaim("locale"));
        assertEquals("12345", jwtClaimsSet.getStringClaim("preferred_username"));
        assertEquals("56789", jwtClaimsSet.getStringClaim("ext_id"));
        assertEquals("U11111111", jwtClaimsSet.getStringClaim("admin_dir_uid"));
        assertEquals("S1+OK", jwtClaimsSet.getStringClaim("login_level"));
        assertEquals("S1+OK", jwtClaimsSet.getStringClaim("login_level"));
        assertEquals("12345", jwtClaimsSet.getStringClaim("sub"));
        assertEquals(singletonList("test-client-bpscoped"), jwtClaimsSet.getStringListClaim("aud"));
        assertNotNull(jwtClaimsSet.getDateClaim("exp"));
        assertNotNull(jwtClaimsSet.getDateClaim("iat"));
        assertTrue(jwtClaimsSet.getStringClaim("iss").startsWith("http://localhost:"));
        assertEquals("ThisisaTest", jwtClaimsSet.getStringClaim("nonce"));
        assertEquals(singletonList("bprolea"), jwtClaimsSet.getJSONObjectClaim("bproles").get("12345"));
        assertEquals(singletonList("bproleb"), jwtClaimsSet.getJSONObjectClaim("bproles").get("12346"));
        assertEquals("some-custom-claim1-value", jwtClaimsSet.getStringClaim("some-custom-claim1"));
        assertEquals("some-custom-claim2-value", jwtClaimsSet.getJSONObjectClaim("some-custom-claim2").get("0"));
        assertNull(jwtClaimsSet.getClaim("scope"));
    }

    @Test
    void tokenRequest_bpScopedClient_shouldReturnIDToken_withoutBpRoles() throws ParseException {
        String idToken = retrieveTokenUsingAuthCodeFlow("id_token", "test-client-bpscoped", Set.of(), Set.of("12345:bprole"));

        JWTClaimsSet jwtClaimsSet = TestTokenParser.parseJwtClaims(idToken);
        assertEquals("Henriette Muster", jwtClaimsSet.getStringClaim("name"));
        assertEquals("Henriette", jwtClaimsSet.getStringClaim("given_name"));
        assertEquals("Muster", jwtClaimsSet.getStringClaim("family_name"));
        assertEquals("DE", jwtClaimsSet.getStringClaim("locale"));
        assertEquals("12345", jwtClaimsSet.getStringClaim("preferred_username"));
        assertEquals("56789", jwtClaimsSet.getStringClaim("ext_id"));
        assertEquals("U11111111", jwtClaimsSet.getStringClaim("admin_dir_uid"));
        assertEquals("S1+OK", jwtClaimsSet.getStringClaim("login_level"));
        assertEquals("S1+OK", jwtClaimsSet.getStringClaim("login_level"));
        assertEquals("12345", jwtClaimsSet.getStringClaim("sub"));
        assertEquals(singletonList("test-client-bpscoped"), jwtClaimsSet.getStringListClaim("aud"));
        assertNotNull(jwtClaimsSet.getDateClaim("exp"));
        assertNotNull(jwtClaimsSet.getDateClaim("iat"));
        assertTrue(jwtClaimsSet.getStringClaim("iss").startsWith("http://localhost:"));
        assertEquals("ThisisaTest", jwtClaimsSet.getStringClaim("nonce"));
        assertNull(jwtClaimsSet.getClaim("bproles"));
        assertEquals("some-custom-claim1-value", jwtClaimsSet.getStringClaim("some-custom-claim1"));
        assertEquals("some-custom-claim2-value", jwtClaimsSet.getJSONObjectClaim("some-custom-claim2").get("0"));
        assertNull(jwtClaimsSet.getClaim("scope"));
    }

    @Test
    void userInfoEndpoint_shouldReturnUserInfo() {
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token");

        JsonPath jsonPath = callUserInfoEndpoint(accessToken);

        // If the response is a JSON object with fields:
        assertThat(jsonPath.getString("name"), equalTo("Henriette Muster"));
        assertThat(jsonPath.getString("given_name"), equalTo("Henriette"));
        assertThat(jsonPath.getString("family_name"), equalTo("Muster"));
        assertThat(jsonPath.getString("locale"), equalTo("DE"));
        assertThat(jsonPath.getString("preferred_username"), equalTo("12345"));
        assertThat(jsonPath.getString("ext_id"), equalTo("56789"));
        assertThat(jsonPath.getString("admin_dir_uid"), equalTo("U11111111"));
        assertThat(jsonPath.getString("login_level"), equalTo("S1+OK"));
        assertThat(jsonPath.getMap("bproles"), equalTo(Map.of("12345", List.of("bprole"))));
    }

    @Test
    void userInfoEndpoint_bpScopeEnabled_shouldReturnUserInfoWithAllBpRoles() {
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token", "test-client-bpscoped", Set.of("bproles:*"), Set.of("1:userbprolea", "2:userbproleb"));

        JsonPath jsonPath = callUserInfoEndpoint(accessToken);

        assertThat(jsonPath.getMap("bproles"), equalTo(Map.of("1", List.of("userbprolea"), "2", List.of("userbproleb"))));
    }

    @Test
    void userInfoEndpoint_bpScopeEnabledWithoutScopes_shouldReturnUserInfoWithoutBpRoles() {
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token", "test-client-bpscoped", Set.of(), Set.of("1:userbprolea", "2:userbproleb"));

        JsonPath jsonPath = callUserInfoEndpoint(accessToken);

        assertNull(jsonPath.getMap("bproles"));
    }

    @Test
    void userInfoEndpoint_bpScopeEnabledOnlyOneBpInScope_shouldReturnUserInfoWithBpRolesForOneBp() {
        String accessToken = retrieveTokenUsingAuthCodeFlow("access_token", "test-client-bpscoped", Set.of("bproles:2"), Set.of("1:userbprolea", "2:userbproleb"));

        JsonPath jsonPath = callUserInfoEndpoint(accessToken);

        assertThat(jsonPath.getMap("bproles"), equalTo(Map.of( "2", List.of("userbproleb"))));
    }

    private JsonPath callUserInfoEndpoint(String accessToken) {
        Response response =  request()
                .header(HttpHeaders.AUTHORIZATION, TokenType.BEARER.getValue() + " " + accessToken)
                .when()
                .get("/userinfo")
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .response();

        return response.jsonPath();
    }

    @Test
    void userInfoEndpoint_shouldForwardToLoginWithoutToken() {
        request().get("/userinfo")
                .then()
                .assertThat()
                .statusCode(302)
                .header(HttpHeaders.LOCATION, endsWith(CustomLoginController.LOGIN_FORM_PATH));
    }

}
