package com.example.authserver;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class AuthServerConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient spa = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("spa-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://app.example.com/auth/callback")
                .scope("payments")
                .clientSettings(cs -> cs.requireProofKey(true))
                .tokenSettings(ts -> ts.accessTokenTimeToLive(Duration.ofMinutes(30)))
                .build();
        return new InMemoryRegisteredClientRepository(spa);
    }

    @Bean
    public AuthorizationServerSettings providerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("https://auth.example.com")
                .build();
    }

    @Bean
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.formLogin(); // enable form login for interactive authentication
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Simple RSA key generation for demo (store keys securely in prod)
    @Bean
    public RSAKey rsaJwk() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair kp = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }
}
