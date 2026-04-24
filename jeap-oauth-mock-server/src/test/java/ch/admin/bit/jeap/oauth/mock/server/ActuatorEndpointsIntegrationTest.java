package ch.admin.bit.jeap.oauth.mock.server;

import io.restassured.RestAssured;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.Test;
import org.springframework.boot.micrometer.metrics.test.autoconfigure.AutoConfigureMetrics;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@AutoConfigureMetrics
class ActuatorEndpointsIntegrationTest {

    @LocalServerPort
    int localServerPort;

    @Test
    void publicActuatorEndpoint_shouldBeAccessibleWithoutAuthentication() {
        request().get("/actuator/health")
                .then()
                .assertThat()
                .statusCode(200);

        request().get("/actuator/info")
                .then()
                .assertThat()
                .statusCode(200);
    }

    @Test
    void protectedActuatorEndpoint_shouldBeAccessibleWithAuthentication() {
        request().get("/actuator/prometheus")
                .then()
                .assertThat()
                .statusCode(401);

        request().auth().basic("prometheus", "secret")
                .get("/actuator/prometheus")
                .then()
                .assertThat()
                .statusCode(200);
    }

    private RequestSpecification request() {
        return RestAssured.given().port(localServerPort);
    }

}
