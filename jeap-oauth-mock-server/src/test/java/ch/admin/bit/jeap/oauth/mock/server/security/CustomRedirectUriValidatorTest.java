package ch.admin.bit.jeap.oauth.mock.server.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class CustomRedirectUriValidatorTest {
    private SecurityConfig.CustomRedirectUriValidator validator;
    private OAuth2AuthorizationCodeRequestAuthenticationContext context;
    private OAuth2AuthorizationCodeRequestAuthenticationToken token;
    private RegisteredClient registeredClient;

    @BeforeEach
    void setUp() {
        validator = new SecurityConfig.CustomRedirectUriValidator();
        context = mock(OAuth2AuthorizationCodeRequestAuthenticationContext.class);
        token = mock(OAuth2AuthorizationCodeRequestAuthenticationToken.class);
        registeredClient = mock(RegisteredClient.class);

        when(context.getAuthentication()).thenReturn(token);
        when(context.getRegisteredClient()).thenReturn(registeredClient);
    }

    @ParameterizedTest
    @MethodSource("provideRedirectUriTestCases")
    void validateRedirectUri(String requestedUri, Set<String> registeredUris, boolean shouldThrow) {
        when(token.getRedirectUri()).thenReturn(requestedUri);
        when(registeredClient.getRedirectUris()).thenReturn(registeredUris);

        if (shouldThrow) {
            assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class, () -> validator.accept(context));
        } else {
            validator.accept(context);
            verify(context).getAuthentication();
            verify(context).getRegisteredClient();
        }
    }

    private static Stream<Arguments> provideRedirectUriTestCases() {
        return Stream.of(
                Arguments.of("https://valid.com/callback", Set.of("https://valid.com/callback"), false),
                Arguments.of("https://valid.com/callback", Set.of("https://valid.com/*"), false),
                Arguments.of("https://invalid.com/callback", Set.of("https://valid.com/callback"), true),
                Arguments.of(null, Set.of("https://valid.com/callback"), true),
                Arguments.of("https://valid.com/callback", Set.of("https://valid.com/call*"), false),
                Arguments.of("https://invalid.com/callback", Set.of("https://valid.com/call*"), true)
        );
    }
}
