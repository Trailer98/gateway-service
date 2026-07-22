package com.selflearning.gatewayservice.auth;

public record TokenValidateRequest(
        String token
) {
}
