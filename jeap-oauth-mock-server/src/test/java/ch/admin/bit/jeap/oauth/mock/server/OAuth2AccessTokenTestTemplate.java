package ch.admin.bit.jeap.oauth.mock.server;

import lombok.Builder;
import lombok.Singular;
import lombok.Value;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.util.Set;

import static java.lang.String.format;

class OAuth2AccessTokenTestTemplate {

    @Builder
    @Value
    static class TestClientConfig {
        String clientId;
        @Singular
        Set<String> scopes;
    }

    private static final String REGISTRATION_ID = "test";

    private final TestClientConfig clientConfig;
    private final int localServerPort;

    OAuth2AccessTokenTestTemplate(TestClientConfig clientConfig, int localServerPort) {
        this.clientConfig = clientConfig;
        this.localServerPort = localServerPort;
    }

    OAuth2AccessToken requestAccessToken() {
        ClientRegistrationRepository clientRegistrations = getRegistration(clientConfig, localServerPort);
        OAuth2AuthorizedClientService clientService = new InMemoryOAuth2AuthorizedClientService(clientRegistrations);
        AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrations, clientService);
        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .clientCredentials()
                        .build();
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(REGISTRATION_ID)
                .principal("anonymous")
                .build();
        OAuth2AuthorizedClient client = authorizedClientManager.authorize(authorizeRequest);

        return client.getAccessToken();
    }

    private ClientRegistrationRepository getRegistration(TestClientConfig clientConfig, int localServerPort) {
        ClientRegistration registration = ClientRegistration
                .withRegistrationId(REGISTRATION_ID)
                .tokenUri(format("http://localhost:%d/oauth2/token", localServerPort))
                .clientId(clientConfig.getClientId())
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope(clientConfig.getScopes())
                .build();
        return new InMemoryClientRegistrationRepository(registration);
    }
}
