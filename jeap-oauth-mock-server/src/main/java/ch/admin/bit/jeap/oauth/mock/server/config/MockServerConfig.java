package ch.admin.bit.jeap.oauth.mock.server.config;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;

/**
 * General configuration of the mock-server instance
 */
@Component
@ConfigurationProperties(prefix = "mockserver")
@Data
@Slf4j
public
class MockServerConfig {
    /**
     * Name of the keystore file to use, normally this should not be changed
     */
    private String jwtKeystoreName = "/mockserver.jks";
    /**
     * Secret of the keystore file to use, normally this should not be changed
     */
    private String jwtKeystoreSecret = "secret";
    /**
     * Alias of the key in the keystore file to use, normally this should not be changed
     */
    private String jwtKeypairAlias = "mockserver";
    /**
     * Secret of the key in the keystore file to use, normally this should not be changed
     */
    private String jwtKeypairSecret = "secret";
    /**
     * Base-URL of where the oauth mock server is reachable. Change this e.g. if you change the port, hostname of path
     */
    private String baseUrl = "http://localhost:8180";

    @PostConstruct
    void log() {
        log.info("Base URL: {}", baseUrl);
    }
}
