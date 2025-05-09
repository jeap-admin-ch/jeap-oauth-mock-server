package ch.admin.bit.jeap.oauth.mock.server.security;

import ch.admin.bit.jeap.oauth.mock.server.config.ClientData;
import ch.admin.bit.jeap.oauth.mock.server.config.MockServerConfig;
import ch.admin.bit.jeap.oauth.mock.server.config.OAuthMockData;
import ch.admin.bit.jeap.oauth.mock.server.config.OAuthMockData.UserData;
import ch.admin.bit.jeap.oauth.mock.server.login.CustomLoginController;
import ch.admin.bit.jeap.oauth.mock.server.login.CustomLoginDetails;
import ch.admin.bit.jeap.oauth.mock.server.login.ForceLoginFormFilter;
import ch.admin.bit.jeap.oauth.mock.server.token.PamsJwtAccessTokenCustomizer;
import ch.admin.bit.jeap.oauth.mock.server.token.UserInfoMapper;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import jakarta.servlet.DispatcherType;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ResolvableType;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.stream.Collectors.toList;

@Configuration
@Slf4j
public class SecurityConfig {
    private static final String SECRET = "secret";

    private static final String ANY = "*";

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();
        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                .authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().authenticated()
                );

        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
        http.addFilterBefore(
                new ForceLoginFormFilter(), LogoutFilter.class);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint
                                .authenticationProviders(configureAuthenticationValidator())
                )
                .tokenIntrospectionEndpoint(tokenIntrospectionEndpoint ->
                        tokenIntrospectionEndpoint
                                .authenticationProviders(configureAuthenticationValidator())
                )
                // Enable OpenID Connect 1.0
                .oidc(oidc ->
                        oidc.userInfoEndpoint(userInfoEndpoint ->
                                userInfoEndpoint.userInfoMapper(new UserInfoMapper())));

        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint(CustomLoginController.LOGIN_FORM_PATH))
                )
                // Accept access tokens for User Info
                .oauth2ResourceServer(c -> c.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @SuppressWarnings("Convert2MethodRef")
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
        http.csrf(c -> c.disable());
        http.headers(h -> h
                .frameOptions(f -> f.disable())
                .contentSecurityPolicy(p -> p.policyDirectives("frame-ancestors 'self' http://*:* https://*:*")));

        http
                .authorizeHttpRequests((authorize) -> {
                            authorize.requestMatchers(CustomLoginController.LOGIN_FORM_PATH).permitAll();
                            authorize.requestMatchers("/styles/**").permitAll();
                            authorize.requestMatchers("/favicon.ico").permitAll();
                            authorize.requestMatchers("/.well-known/**").permitAll();
                            authorize.requestMatchers("/protocol/**").permitAll();
                            authorize.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll();
                            authorize.anyRequest().authenticated();
                        }
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(c -> c
                        .authenticationDetailsSource(CustomLoginDetails::fromRequest)
                        .loginPage(CustomLoginController.LOGIN_FORM_PATH));

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin(ANY);
        configuration.addAllowedHeader(ANY);
        configuration.addAllowedMethod(ANY);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/userinfo", configuration);
        source.registerCorsConfiguration("/.well-known/**", configuration);
        source.registerCorsConfiguration("/protocol/**", configuration);
        source.registerCorsConfiguration("/oauth2/**", configuration);
        return source;
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(OAuthMockData oAuthMockData) {
        return new InMemoryRegisteredClientRepository(oAuthMockData.getClients().stream()
                .map(ClientData::toRegisteredClient)
                .collect(toList()));
    }

    @Bean
    public UserDetailsService userDetailsService(OAuthMockData oAuthMockData) {
        List<UserDetails> userDetails = oAuthMockData.getUsers().stream()
                .map(this::createUserDetails)
                .collect(Collectors.toList());

        return new InMemoryUserDetailsManager(userDetails);
    }

    private UserDetails createUserDetails(UserData userData) {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        return User.builder()
                .passwordEncoder(encoder::encode)
                .username(userData.getId())
                .password(SECRET)
                .authorities(List.of())
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) throws CertificateException, OperatorCreationException, NoSuchAlgorithmException {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = getRsaKey(keyPair, privateKey, publicKey);
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    private static RSAKey getRsaKey(KeyPair keyPair, RSAPrivateKey privateKey, RSAPublicKey publicKey) throws OperatorCreationException, CertificateException, NoSuchAlgorithmException {
        X509Certificate certificate = getX509Certificate(keyPair, privateKey);

        // Convert to DER format and Base64 encode
        byte[] derEncoded = certificate.getEncoded();
        String base64Encoded = Base64.getEncoder().encodeToString(derEncoded);

        // Compute SHA-1 and SHA-256 thumbprints
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Digest = sha1.digest(derEncoded);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] sha256Digest = sha256.digest(derEncoded);

        // x5t is deprecated, but still used by keycloak
        //noinspection deprecation
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .x509CertChain(List.of(com.nimbusds.jose.util.Base64.encode(derEncoded)))
                .x509CertThumbprint(Base64URL.encode(sha1Digest))
                .x509CertSHA256Thumbprint(Base64URL.encode(sha256Digest))
                .algorithm(Algorithm.parse("RS256"))
                .build();
    }

    private static X509Certificate getX509Certificate(KeyPair keyPair, RSAPrivateKey privateKey) throws OperatorCreationException, CertificateException {
        // Create the X.509 certificate
        X500Name issuer = new X500Name("CN=Mock Server CA, O=jEAP, L=Bern, ST=Bern, C=Switzerland");
        X500Name subject = new X500Name("CN=Mock Subject, O=jEAP, L=Bern, ST=Bern, C=Switzerland");

        BigInteger serialNumber = new BigInteger(64, new java.security.SecureRandom());
        Date notBefore = new Date(System.currentTimeMillis() - DAYS.toMillis(24));
        Date notAfter = new Date(System.currentTimeMillis() + DAYS.toMillis(365));

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuer, serialNumber, notBefore, notAfter, subject, keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(privateKey);
        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certificateHolder);
    }

    /**
     * The public/private key pair used to sign JWT tokens
     */
    @Bean
    KeyPair keyPair(MockServerConfig mockServerConfig) {
        // Generate new RSA key at startup using JCA, used for signing JWTs
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException gse) {
            throw new IllegalStateException("Unable to create RSA key pair. Maybe there is a problem with the cryptography provider?", gse);
        }
    }

    /**
     * Spring Auth Server OAuth2ConfigurerUtils#getOptionalBean() does not take @Primary into account when resolving
     * a token customizer. A custom post processor is thus used here, registering the default token customizer only
     * when no other customizer has been provided.
     */
    @Bean
    public BeanFactoryPostProcessor beanFactoryPostProcessor() {
        return factory -> {
            BeanDefinitionRegistry registry = (BeanDefinitionRegistry) factory;
            if (!isBeanCustomizerRegistered(factory)) {
                registry.registerBeanDefinition("tokenCustomizer",
                        BeanDefinitionBuilder.genericBeanDefinition(PamsJwtAccessTokenCustomizer.class).getBeanDefinition()
                );
            }
        };
    }

    private static boolean isBeanCustomizerRegistered(ConfigurableListableBeanFactory factory) {
        String[] existingBeanCustomizerBeans = factory.getBeanNamesForType(
                ResolvableType.forClassWithGenerics(OAuth2TokenCustomizer.class, JwtEncodingContext.class));
        return existingBeanCustomizerBeans.length > 0;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(MockServerConfig mockServerConfig) {
        return AuthorizationServerSettings.builder()
                .issuer(mockServerConfig.getBaseUrl())
                // Customize JWKS path for backward compatibility with the mockserver 1.x
                .jwkSetEndpoint("/.well-known/jwks.json")
                .build();
    }

    /**
     * Override default redirect_uri validator to allow for redirect URIs with "localhost" and override scope validation to allow dynamic scopes.
     * See <a href="https://docs.spring.io/spring-authorization-server/docs/0.4.0/reference/html/protocol-endpoints.html#oauth2-authorization-endpoint">Docs</a>
     */
    private Consumer<List<AuthenticationProvider>> configureAuthenticationValidator() {
        return (authenticationProviders) ->
                authenticationProviders.forEach((authenticationProvider) -> {
                    if (authenticationProvider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider oauthProvider) {
                        Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator =
                                // Override default redirect_uri validator to allow for redirect URIs with "localhost"
                                new CustomRedirectUriValidator()
                                        // Override default scope validator to allow dynamic scopes
                                        .andThen(SecurityConfig::validateScopeSupportingDynamicScopes);
                        oauthProvider.setAuthenticationValidator(authenticationValidator);
                    }
                });
    }

    // Replacing the default scope validator from OAuth2AuthorizationCodeRequestAuthenticationValidator in order to
    // support the dynamic scopes of Keycloak.
    private static void validateScopeSupportingDynamicScopes(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = authenticationContext.getAuthentication();
        RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
        Set<String> requestedScopes = authorizationCodeRequestAuthentication.getScopes();
        Set<String> allowedScopes = registeredClient.getScopes();
        if (!requestedScopesMatchingAllowedScopes(requestedScopes, allowedScopes)) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE, "OAuth 2.0 Parameter: " + OAuth2ParameterNames.SCOPE,
                    "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1");
            String redirectUri = StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri()) ?
                    authorizationCodeRequestAuthentication.getRedirectUri() :
                    registeredClient.getRedirectUris().iterator().next();
            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
                    new OAuth2AuthorizationCodeRequestAuthenticationToken(
                            authorizationCodeRequestAuthentication.getAuthorizationUri(), authorizationCodeRequestAuthentication.getClientId(),
                            (Authentication) authorizationCodeRequestAuthentication.getPrincipal(), redirectUri,
                            authorizationCodeRequestAuthentication.getState(), authorizationCodeRequestAuthentication.getScopes(),
                            authorizationCodeRequestAuthentication.getAdditionalParameters());
            authorizationCodeRequestAuthenticationResult.setAuthenticated(true);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authorizationCodeRequestAuthenticationResult);
        }
    }

    /**
     * Validate the requested scopes of an authentication against the scopes allowed for a client. Supports dynamic scopes,
     * i.e. an allowed scope "bproles:*" will match e.g. the requested scope "bproles:1232354".
     *
     * @param requestedScopes The scopes requested by an authentication
     * @param allowedScopes   The scopes allowed by the client
     * @return <code>true</code> if the requested scopes are contained within the allowed scopes, <code>false</code> otherwise.
     */
    public static boolean requestedScopesMatchingAllowedScopes(Set<String> requestedScopes, Set<String> allowedScopes) {
        Set<String> dynamicScopes = allowedScopes.stream().filter(s -> s.endsWith(":*")).collect(Collectors.toSet());
        Set<String> allowedPlainScopes = allowedScopes.stream().filter(s -> !dynamicScopes.contains(s)).collect(Collectors.toSet());
        Set<String> requestedPlainScopes = requestedScopes.stream().
                filter(s -> dynamicScopes.stream().noneMatch(d -> s.startsWith(d.substring(0, d.length() - 1)))).
                collect(Collectors.toSet());
        return requestedPlainScopes.isEmpty() || allowedPlainScopes.containsAll(requestedPlainScopes);
    }

    static class CustomRedirectUriValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {
        @Override
        public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = authenticationContext.getAuthentication();
            RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
            String requestedRedirectUri = authorizationCodeRequestAuthentication.getRedirectUri();

            // Use exact or wildcard matching when comparing client redirect URIs against pre-registered URIs
            if (registeredClient.getRedirectUris().stream().noneMatch(uri -> {
                if (requestedRedirectUri == null) return false;
                return uri.endsWith("*") ? requestedRedirectUri.startsWith(uri.substring(0, uri.length() - 1)) : requestedRedirectUri.equals(uri);
            })) {
                logAndThrowError(requestedRedirectUri, registeredClient);
            }
        }

        private void logAndThrowError(String requestedRedirectUri, RegisteredClient registeredClient) {
            String msg = String.format("The redirect_uri %s is not valid for the client %s. Expected the redirect uri to match one of: %s}.", requestedRedirectUri, registeredClient.getClientId(), registeredClient.getRedirectUris());
            log.error(msg);

            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, msg, null);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
    }
}
