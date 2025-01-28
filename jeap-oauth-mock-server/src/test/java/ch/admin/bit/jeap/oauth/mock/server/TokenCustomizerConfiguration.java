package ch.admin.bit.jeap.oauth.mock.server;

import ch.admin.bit.jeap.oauth.mock.server.token.AbstractJwtTokenCustomizer;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Map;

@TestConfiguration
class TokenCustomizerConfiguration {

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return new TestClaimCustomizer();
    }

    static class TestClaimCustomizer extends AbstractJwtTokenCustomizer {
        static final String TEST_CLAIM = "test-claim";
        static final String ACCESS_TOKEN_VALUE = "access-token-value";
        static final String ID_TOKEN_VALUE = "id-token-value";

        @Override
        protected void customizeAccessToken(JwtEncodingContext context, Map<String, Object> claims) {
            claims.put(TEST_CLAIM, ACCESS_TOKEN_VALUE);
        }

        @Override
        protected void customizeIdToken(JwtEncodingContext context, Map<String, Object> claims) {
            claims.put(TEST_CLAIM, ID_TOKEN_VALUE);
        }
    }
}
