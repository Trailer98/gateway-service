package com.selflearning.gatewayservice.auth;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "gateway.auth")
public record AuthProperties(
        String tokenValidationUri,
        Duration tokenValidationTimeout,
        List<String> whitelistPaths
) {

    private static final String DEFAULT_TOKEN_VALIDATION_URI = "http://auth-service/auth/internal/token/validate";

    public AuthProperties {
        tokenValidationUri = tokenValidationUri == null || tokenValidationUri.isBlank()
                ? DEFAULT_TOKEN_VALIDATION_URI
                : tokenValidationUri;
        tokenValidationTimeout = tokenValidationTimeout == null
                ? Duration.ofSeconds(3)
                : tokenValidationTimeout;
        whitelistPaths = whitelistPaths == null
                ? List.of("/api/auth/login", "/api/auth/refresh", "/actuator/**", "/favicon.ico")
                : List.copyOf(whitelistPaths);
    }
}
