package ch.admin.bit.jeap.oauth.mock.server.config;

import ch.admin.bit.jeap.web.configuration.HttpHeaderFilterPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;

import java.util.Map;

@Configuration
public class WebHeaderConfig {

    /**
     * The web-config-starter's {@code AddHeadersFilter} applies a long-lived {@code Cache-Control: public, max-age=604800}
     * to dynamic endpoints (e.g. {@code /openIdMockServerLogin}), causing the login/logout forms and their
     * error responses to be cached by the browser. Removing its {@code Cache-Control}/{@code Expires} headers here lets
     * Spring Security emit {@code no-store} instead, disabling caching while keeping all the starter's security headers.
     */
    @Bean
    public HttpHeaderFilterPostProcessor noCacheHttpHeaderFilterPostProcessor() {
        return new HttpHeaderFilterPostProcessor() {
            @Override
            public void postProcessHeaders(Map<String, String> headers, String method, String path) {
                headers.remove(HttpHeaders.CACHE_CONTROL);
                headers.remove(HttpHeaders.EXPIRES);
            }
        };
    }
}
