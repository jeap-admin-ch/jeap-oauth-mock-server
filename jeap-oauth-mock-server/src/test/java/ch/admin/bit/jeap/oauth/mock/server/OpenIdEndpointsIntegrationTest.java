package ch.admin.bit.jeap.oauth.mock.server;

import io.restassured.RestAssured;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.hamcrest.Matchers.*;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "mockserver.base-url=http://external-hostname")
@ActiveProfiles("test")
class OpenIdEndpointsIntegrationTest {

    @LocalServerPort
    int localServerPort;

    @Test
    void publicWellKnownEndpoints_shouldBeAccessibleWithoutAuthenthication() {
        String keys = request().get("/.well-known/jwks.json")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, startsWith(MediaType.APPLICATION_JSON_VALUE))
                .body("keys", hasSize(greaterThan(0)))
                .extract().body().asString();

        String protocolCertKeys = request().get("/protocol/openid-connect/certs")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, startsWith(MediaType.APPLICATION_JSON_VALUE))
                .body("keys", hasSize(greaterThan(0)))
                .body("keys[0].kty", equalTo("RSA"))
                .body("keys[0].x5c", hasSize(greaterThan(0)))
                .body("keys[0].x5t", not(emptyString()))
                .body("keys[0].'x5t#S256'", not(emptyString()))
                .body("keys[0].alg", equalTo("RS256"))
                .extract().body().asString();

        assertThat(protocolCertKeys)
                .isEqualToIgnoringWhitespace(keys);

        request().get("/.well-known/openid-configuration")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, startsWith(MediaType.APPLICATION_JSON_VALUE))
                .body("issuer", equalTo("http://external-hostname"));
    }

    private RequestSpecification request() {
        return RestAssured.given()
                .port(localServerPort)
                .redirects().follow(false);
    }
}
