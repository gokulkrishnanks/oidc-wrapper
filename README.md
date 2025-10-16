# Auth Server POC (Spring Authorization Server)

This is a minimal proof-of-concept Spring Boot project that demonstrates an Authorization Server
(Authorization Code + PKCE) integrated with an external IdP via REST endpoints.

**Important:** This is a POC for development and testing only. Do not use as-is in production.
- Keys are generated on startup (not secure).
- In-memory client/authorization storage (not persistent).
- Blocking WebClient usage in authentication provider for brevity.
- TLS is not configured here; run behind a TLS reverse proxy in prod.

## How to run

1. Build with Maven:
   ```
   mvn clean package
   ```

2. Run:
   ```
   mvn spring-boot:run
   ```

3. Visit the authorization endpoint with PKCE-enabled flow from your SPA:
   ```
   https://localhost:8443/oauth2/authorize?response_type=code&client_id=spa-client&redirect_uri=https://app.example.com/auth/callback&scope=payments&state=xyz&code_challenge=...&code_challenge_method=S256
   ```

## Where to customize
- `IdpAuthenticationProvider` - adapt to your IdP API, implement OTP flows and non-blocking calls.
- Replace in-memory `RegisteredClientRepository` with JDBC-backed repo for persistence.
- Replace RSA key generation with secure key management (Vault/HSM).
- Harden security: rate-limiting, CSP, input validation, logging, monitoring.

If you want, I can also:
- add Redis-backed authorization code storage,
- wire a simple SPA example showing PKCE generation and token exchange,
- or convert blocking WebClient to reactive flow.
