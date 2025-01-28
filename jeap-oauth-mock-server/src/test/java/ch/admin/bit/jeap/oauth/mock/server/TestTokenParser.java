package ch.admin.bit.jeap.oauth.mock.server;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.experimental.UtilityClass;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.text.ParseException;

@UtilityClass
class TestTokenParser {

    static JWTClaimsSet parseJwtClaims(OAuth2AccessToken accessToken) throws ParseException {
        String value = accessToken.getTokenValue();
        JWT jwt = SignedJWT.parse(value);
        return jwt.getJWTClaimsSet();
    }

    static JWTClaimsSet parseJwtClaims(String tokenValue) throws ParseException {
        JWT jwt = SignedJWT.parse(tokenValue);
        return jwt.getJWTClaimsSet();
    }
}
