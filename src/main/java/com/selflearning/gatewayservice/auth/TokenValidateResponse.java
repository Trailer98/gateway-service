package com.selflearning.gatewayservice.auth;

import java.time.Instant;

public record TokenValidateResponse(
        boolean valid,
        Long userId,
        String username,
        String sessionId,
        String tokenId,
        Instant expiresAt
) {
}
