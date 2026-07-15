package ch.admin.bit.jeap.oauth.mock.server.security;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.X509CertUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression test for JEAP-7270: Bouncycastle 1.85 rejects X.500 country code attributes that are not
 * exactly two characters per ISO 3166-1, failing the application startup when the JWK signing certificate
 * is created with a country attribute like 'Switzerland'.
 */
@SpringBootTest
@ActiveProfiles("test")
class SecurityConfigCertificateTest {

    @Autowired
    private JWKSource<SecurityContext> jwkSource;

    @Test
    void jwkSourceCertificate_shouldUseTwoLetterCountryCode() throws Exception {
        List<JWK> jwks = jwkSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
        assertThat(jwks).isNotEmpty();

        X509Certificate certificate = X509CertUtils.parse(jwks.getFirst().getX509CertChain().getFirst().decode());
        assertThat(certificate).isNotNull();

        assertThat(countryCode(certificate.getSubjectX500Principal().getEncoded())).isEqualTo("CH");
        assertThat(countryCode(certificate.getIssuerX500Principal().getEncoded())).isEqualTo("CH");
    }

    private static String countryCode(byte[] encodedX500Principal) {
        X500Name name = X500Name.getInstance(encodedX500Principal);
        return IETFUtils.valueToString(name.getRDNs(BCStyle.C)[0].getFirst().getValue());
    }
}
