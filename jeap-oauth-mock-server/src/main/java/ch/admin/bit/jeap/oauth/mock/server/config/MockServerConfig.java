package ch.admin.bit.jeap.oauth.mock.server.config;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * General configuration of the mock-server instance
 */
@Component
@ConfigurationProperties(prefix = "mockserver")
@Data
@Slf4j
public class MockServerConfig {
    /**
     * Base-URL of where the oauth mock server is reachable. Change this e.g. if you change the port, hostname of path
     */
    private String baseUrl = "http://localhost:8180";

    /**
     * Default value of the check mode of the audience. Default is OFF.
     * This value can be overridden in the client configuration.
     */
    private IntrospectionEndpointAudienceCheck introspectionEndpointAudienceCheck = IntrospectionEndpointAudienceCheck.OFF;

    @PostConstruct
    void log() {
        log.info("Base URL: {}, introspectionEndpointAudienceCheck: {}", baseUrl, introspectionEndpointAudienceCheck);
    }
}
