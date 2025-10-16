package com.example.authserver;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;
import java.util.Map;

@Component
public class IdpAuthenticationProvider implements AuthenticationProvider {

    private final WebClient webClient;

    public IdpAuthenticationProvider(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl("https://idp.internal").build();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = (String) authentication.getPrincipal();
        String password = authentication.getCredentials() != null ? authentication.getCredentials().toString() : "";

        // POC: synchronous/blocking call for brevity. Replace with non-blocking in production.
        Map resp = this.webClient.post()
                .uri("/validate-password")
                .bodyValue(Map.of("username", username, "password", password))
                .retrieve()
                .bodyToMono(Map.class)
                .block();

        boolean success = resp != null && Boolean.TRUE.equals(resp.get("success"));
        if (!success) {
            return null;
        }

        String subject = resp.getOrDefault("user_id", username).toString();
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(subject, null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        return auth;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
