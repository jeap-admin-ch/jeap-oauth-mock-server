package ch.admin.bit.jeap.oauth.mock.server;

import com.microsoft.playwright.APIResponse;
import com.microsoft.playwright.Browser;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.Request;
import com.microsoft.playwright.options.FormData;
import com.microsoft.playwright.options.RequestOptions;
import org.junit.jupiter.api.*;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end test driving a real (headless) browser to verify the login/logout pages comply with the
 * Content-Security-Policy applied by jeap-spring-boot-web-config-starter. A real browser is the only thing that
 * actually enforces the policy and reports "Refused to execute inline event handler" - the exact failure that
 * shipped when the pages still used inline {@code onchange}/{@code javascript:} handlers.
 * <p>
 * Requires a Playwright Chromium browser to be installed.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"login-page-test"})
class LoginPageCspBrowserIT {

    // PKCE pair: CODE_CHALLENGE is the S256 hash of CODE_VERIFIER. The full-flow test needs the verifier to exchange
    // the authorization code for a token; the CSP-only tests just need the challenge to be well-formed.
    private static final String CODE_VERIFIER = "test-verifier";
    private static final String CODE_CHALLENGE = "JBbiqONGWPaAmwXk_8bT6UnlPfrn65D32eZlJS-zGG0";

    @LocalServerPort
    private int port;

    private static Playwright playwright;
    private static Browser browser;

    private Page page;
    private List<String> browserErrors;

    @BeforeAll
    static void launchBrowser() {
        playwright = Playwright.create();
        browser = playwright.chromium().launch();
    }

    @AfterAll
    static void closeBrowser() {
        if (browser != null) {
            browser.close();
        }
        if (playwright != null) {
            playwright.close();
        }
    }

    @BeforeEach
    void openPage() {
        page = browser.newPage();
        browserErrors = new CopyOnWriteArrayList<>();
        page.onConsoleMessage(message -> {
            if ("error".equals(message.type())) {
                browserErrors.add(message.text());
            }
        });
        page.onPageError(browserErrors::add);
    }

    @AfterEach
    void closePage() {
        if (page != null) {
            page.close();
        }
    }

    @Test
    void loginForm_switchingUser_runsExternalScriptWithoutCspViolation() {
        page.navigate(authorizeUrl());
        page.waitForSelector("#username");

        // Switching users must run the change handler from login.js. If that ever regresses to an inline onchange
        // attribute, the browser refuses to execute it under script-src 'self' and reports a CSP violation.
        page.selectOption("#username", "another-user");
        page.waitForURL("**/openIdMockServerLogin?user=another-user");

        assertNoCspViolations();
    }

    @Test
    void logoutPage_loadsWithoutCspViolation() {
        page.navigate("http://localhost:" + port + "/openIdMockServerLogin?logout");
        page.waitForSelector("#back-link");

        assertNoCspViolations();
    }

    @Test
    void fullAuthorizationCodeFlow_throughBrowser_yieldsAccessToken() {
        page.navigate(authorizeUrl());
        page.waitForSelector("#submit-button");

        // Submit the actual rendered login form (default user "user", hidden password "secret") and capture the
        // authorization code from the redirect the server issues to the client's (here non-served) redirect_uri.
        Request redirectRequest = page.waitForRequest(
                request -> request.url().startsWith("http://localhost/redirect"),
                () -> page.click("#submit-button"));

        assertNoCspViolations();

        String code = queryParam(redirectRequest.url(), "code");
        assertThat(code).as("authorization code from redirect").isNotBlank();

        // Exchange the code for a token, completing the authorization-code + PKCE flow end to end.
        APIResponse tokenResponse = page.request().post(
                "http://localhost:" + port + "/oauth2/token",
                RequestOptions.create().setForm(FormData.create()
                        .set("grant_type", "authorization_code")
                        .set("client_id", "test-client")
                        .set("code_verifier", CODE_VERIFIER)
                        .set("code", code)
                        .set("redirect_uri", "http://localhost/redirect")));

        assertThat(tokenResponse.status()).isEqualTo(200);
        assertThat(tokenResponse.text()).contains("access_token");
    }

    private static String queryParam(String url, String name) {
        Matcher matcher = Pattern.compile("[?&]" + name + "=([^&]+)").matcher(url);
        return matcher.find() ? URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8) : null;
    }

    private String authorizeUrl() {
        return "http://localhost:" + port + "/oauth2/authorize"
                + "?response_type=code&client_id=test-client"
                + "&redirect_uri=http://localhost/redirect&scope=openid"
                + "&code_challenge=" + CODE_CHALLENGE + "&code_challenge_method=S256";
    }

    private void assertNoCspViolations() {
        List<String> cspViolations = browserErrors.stream()
                .filter(message -> message.contains("Content Security Policy"))
                .toList();
        assertThat(cspViolations).as("browser-reported CSP violations").isEmpty();
    }
}
