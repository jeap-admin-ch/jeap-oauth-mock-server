package ch.admin.bit.jeap.oauth.mock.server.security;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

@RestController
public class KeycloakLikeCertEndpointRedirectController {

    private final JWKSource<SecurityContext> jwkSource;
    private final JWKSelector jwkSelector;

    public KeycloakLikeCertEndpointRedirectController(JWKSource<SecurityContext> jwkSource) {
        this.jwkSource = jwkSource;
        this.jwkSelector = new JWKSelector(new JWKMatcher.Builder().build());
    }

    @GetMapping("/protocol/openid-connect/certs")
    public void returnJwkSetAtKeycloakCompatibleResourcePath(HttpServletResponse response) throws IOException {
        JWKSet jwkSet = getJwkSet();

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        try (Writer writer = response.getWriter()) {
            writer.write(jwkSet.toString());
        }
    }

    private JWKSet getJwkSet() {
        try {
            return new JWKSet(this.jwkSource.get(this.jwkSelector, null));
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Failed to select the JWK(s) -> " + ex.getMessage(),
                    ex);
        }
    }
}
