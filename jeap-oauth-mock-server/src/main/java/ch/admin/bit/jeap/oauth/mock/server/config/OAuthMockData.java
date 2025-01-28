package ch.admin.bit.jeap.oauth.mock.server.config;

import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.validation.annotation.Validated;

import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Map;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toMap;

/**
 * Actual data to be used by the mock server
 */
@Configuration
@ConfigurationProperties(prefix = "oauth-mock-data")
@Validated
@Data
@Slf4j
public class OAuthMockData {
    @Getter(AccessLevel.NONE)
    private static final List<String> DEFAULT_GRANT_TYPES = asList("authorization_code", "client_credentials", "refresh_token");

    @NotEmpty(message = "at least one oauth client definition is required")
    @NestedConfigurationProperty
    private List<ClientData> clients = emptyList();

    @NestedConfigurationProperty
    private List<UserData> users = emptyList();

    @Bean
    public Map<String, RegisteredClient> clientsById() {
        return clients.stream()
                .collect(toMap(ClientData::getClientId, ClientData::toRegisteredClient));
    }

    @Bean
    public Map<String, UserData> usersById() {
        return users.stream()
                .collect(toMap(UserData::getId, identity()));
    }

    @Bean
    List<UserData> users() {
        return users;
    }

    @PostConstruct
    void validateConfig() {
        clients.forEach(clientData -> log.info("Adding client from configuration: {}", clientData.getClientId()));
        users.forEach(userData -> log.info("Adding User from configuration: {} ({})", userData.getId(), userData.getName()));
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder(toBuilder = true)
    public static class UserData {
        @NotEmpty
        private String id;

        @Builder.Default
        private String givenName = "Henriette";

        @Builder.Default
        private String familyName = "Muster";

        @Builder.Default
        private String email = "henriette@muster.domain";

        @Builder.Default
        private String locale = "DE";

        @Builder.Default
        private String preferredUsername = "1234";

        @Builder.Default
        private String extId = "5678";

        @Builder.Default
        private String adminDirUID = "U11111111";

        /** PAMS specfic property for Quality of Authority */
        @Builder.Default
        private String loginLevel = "S0";

        private String subject;

        @Builder.Default
        private List<String> userroles = emptyList();

        /** PAMS specfic business partner roles */
        @Builder.Default
        private Map<String, List<String>> bproles = emptyMap();

        /** All entries in this map will be set as a claim within the token. */
        @Builder.Default
        private Map<String, Object> additionalClaims = emptyMap();

        public String getName() {
            return givenName + " " + familyName;
        }
    }
}
