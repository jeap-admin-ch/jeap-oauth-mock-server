package ch.admin.bit.jeap.oauth.mock.server;

import ch.admin.bit.jeap.oauth.mock.server.login.CustomLoginController;
import io.restassured.RestAssured;
import io.restassured.builder.RequestSpecBuilder;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import lombok.SneakyThrows;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.restassured.config.RedirectConfig.redirectConfig;
import static io.restassured.config.RestAssuredConfig.newConfig;
import static io.restassured.config.SessionConfig.sessionConfig;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthorizationCodeFlowTestBase {
    @LocalServerPort
    int localServerPort;

    private CookieFilter cookieFilter;

    @BeforeEach
    void setUp() {
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
        cookieFilter = new CookieFilter();
    }

    protected String retrieveTokenUsingAuthCodeFlow(String tokenName) {
        return retrieveTokenUsingAuthCodeFlow(tokenName, "test-client", Set.of(), Set.of("12345:bprole"));
    }

    protected String retrieveTokenUsingAuthCodeFlow(String tokenName, Set<String> bpRoles) {
        return retrieveTokenUsingAuthCodeFlow(tokenName, "test-client", Set.of(), bpRoles);
    }

    protected String retrieveTokenUsingAuthCodeFlow(String tokenName, String clientId, Set<String> additionalScopes, Set<String> userbproles) {
        String codeVerifier = createCodeVerifier();
        String codeChallenge = createCodeChallenge(codeVerifier);

        String loginFormUrl = startOAuthFlow(codeChallenge, clientId, additionalScopes);
        getLoginForm(loginFormUrl); // Not strictly necessary, simulates real client behaviour & adds coverage for the CustomLoginController
        String oauthAuthorizeUrl = postLoginForm(loginFormUrl, userbproles);
        String authCode = getAuthorizationCode(oauthAuthorizeUrl);
        return requestToken(codeVerifier, authCode, tokenName, clientId);
    }

    private static String createCodeVerifier() {
        SecureRandom sr = new SecureRandom();
        byte[] code = new byte[32];
        sr.nextBytes(code);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(code);
    }

    @SneakyThrows
    private static String createCodeChallenge(String codeVerifier) {
        byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(bytes, 0, bytes.length);
        byte[] digest = md.digest();
        return org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(digest);
    }

    private String startOAuthFlow(String codeChallenge, String clientId, Set<String> additionalScopes) {
        Set<String> scopes = new HashSet<>(Set.of("openid","profile"));
        scopes.addAll(additionalScopes);
        return request()
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", "http://localhost/redirect")
                .queryParam("response_type", "code")
                .queryParam("scope", String.join(" ", scopes))
                .queryParam("state", "12345")
                .queryParam("nonce", "ThisisaTest")
                // PKCE
                .queryParam("code_challenge", codeChallenge)
                .queryParam("code_challenge_method", "S256")
                .get("/oauth2/authorize")
                .then()
                .assertThat()
                .statusCode(302)
                .header(HttpHeaders.LOCATION, endsWith(CustomLoginController.LOGIN_FORM_PATH))
                .extract().header(HttpHeaders.LOCATION);
    }

    private void getLoginForm(String loginFormUrl) {
        request().get(loginFormUrl)
                .then()
                .statusCode(200);
    }

    private String postLoginForm(String loginFormUrl, Set<String> userbproles) {
        return request()
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .formParam("username", "user")
                .formParam("password", "secret")
                .formParam("userroles", "userrole")
                .formParam("additionaluserroles", "")
                .formParam("bproles", userbproles)
                .formParam("additionalbproles", "")
                .post(loginFormUrl)
                .then().assertThat()
                .statusCode(302)
                .header(HttpHeaders.LOCATION, containsString("/oauth2/authorize"))
                .extract().header(HttpHeaders.LOCATION);
    }

    private String getAuthorizationCode(String oauthAuthorizeUrl) {
        RequestSpecBuilder doNotReEncodeRedirectUrlParameters = new RequestSpecBuilder().setUrlEncodingEnabled(false);
        String codeRedirectHeader = request()
                .spec(doNotReEncodeRedirectUrlParameters.build())
                .get(oauthAuthorizeUrl)
                .then().assertThat()
                .statusCode(302)
                .header(HttpHeaders.LOCATION, containsString("code="))
                .extract().header(HttpHeaders.LOCATION);


        Matcher codeExtractor = Pattern.compile("code=(.*?)&").matcher(codeRedirectHeader);
        assertTrue(codeExtractor.find());
        return codeExtractor.group(1);
    }

    private String requestToken(String codeVerifier, String authCode, String tokenName, String clientId) {
        Response response = request()
                .formParam("grant_type", "authorization_code")
                .formParam("client_id", clientId)
                .formParam("code_verifier", codeVerifier)
                .formParam("code", authCode)
                .formParam("redirect_uri", "http://localhost/redirect")
                .post("/oauth2/token");

        response.prettyPrint();
        return response.then()
                .assertThat()
                .statusCode(200)
                .body(tokenName, not(emptyOrNullString()))
                .extract().path(tokenName);
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
