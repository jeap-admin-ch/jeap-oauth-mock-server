package ch.admin.bit.jeap.oauth.mock.server;

import ch.admin.bit.jeap.oauth.mock.server.login.CustomLoginController;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.hamcrest.Matchers.*;

/**
 * Guards the response-header contract of the login/logout pages, which is provided by the interplay of
 * jeap-spring-boot-web-config-starter and {@link ch.admin.bit.jeap.oauth.mock.server.config.WebHeaderConfig}.
 * Runs against a real embedded server ({@code RANDOM_PORT}) because the starter's header logic lives in a servlet
 * filter that {@code MockMvc} would not exercise.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"authorization-code-test"})
class LoginPageHeadersIntegrationTest extends AuthorizationCodeFlowTestBase {

    @Test
    void loginForm_isServedWithNoStoreAndStrictScriptCsp() {
        String loginFormUrl = startOAuthFlowToLoginForm();

        request().get(loginFormUrl)
                .then().assertThat()
                .statusCode(200)
                // Caching regression guard: the dynamic form must never be cached (was: public, max-age=604800).
                .header(HttpHeaders.CACHE_CONTROL, allOf(containsString("no-store"), not(containsString("public"))))
                // CSP contract the templates must satisfy: script-src is exactly 'self', so inline scripts are forbidden.
                .header("Content-Security-Policy", containsString("script-src 'self';"));
    }

    @Test
    void logoutPage_isServedWithNoStore() {
        request().get(CustomLoginController.LOGIN_FORM_PATH + "?logout")
                .then().assertThat()
                .statusCode(200)
                .header(HttpHeaders.CACHE_CONTROL, allOf(containsString("no-store"), not(containsString("public"))));
    }

    @Test
    void staticScript_isServedWithNoStore() {
        request().get("/scripts/login.js")
                .then().assertThat()
                .statusCode(200)
                .header(HttpHeaders.CACHE_CONTROL, allOf(containsString("no-store"), not(containsString("public"))));
    }
}
