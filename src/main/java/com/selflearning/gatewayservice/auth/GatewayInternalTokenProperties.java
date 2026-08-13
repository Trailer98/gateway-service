package com.selflearning.gatewayservice.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Binds {@code gateway.internal-token} (env {@code GATEWAY_INTERNAL_TOKEN}) — the shared secret
 * gateway-service stamps onto the {@code X-Gateway-Token} header of every request it forwards, which
 * wms-system's {@code GatewayUserContextInterceptor} checks to trust that a request genuinely came
 * through the gateway rather than hitting wms-system's port directly.
 *
 * <p>Deliberately has no default anywhere (not here, not in any {@code application*.yml}): a deployment
 * that forgets to set {@code GATEWAY_INTERNAL_TOKEN} must fail at startup, not silently run with the
 * well-known {@code local-dev-gateway-token} value that used to be baked into this codebase's config
 * (and was consequently visible to anyone who could read the source). This record's job is to reject that
 * exact failure mode, plus enforce a minimum length so a trivially-guessable short value can't replace it.
 *
 * <p>wms-system declares an equivalent record with the same field name, same minimum length, and the same
 * known-weak-value rejection list — the two projects don't share a library, so the rule is duplicated
 * intentionally to keep both ends enforcing identical policy without introducing a new shared dependency.
 */
@Validated
@ConfigurationProperties(prefix = "gateway")
public record GatewayInternalTokenProperties(
        @NotBlank(message = "gateway.internal-token (GATEWAY_INTERNAL_TOKEN) must be set")
        @Size(min = 32, message = "gateway.internal-token (GATEWAY_INTERNAL_TOKEN) must be at least 32 characters")
        String internalToken
) {

    /** Historical default that used to ship in this repo's application*.yml — never acceptable at runtime. */
    private static final Set<String> KNOWN_WEAK_VALUES = Set.of("local-dev-gateway-token");

    public GatewayInternalTokenProperties {
        if (internalToken != null && KNOWN_WEAK_VALUES.contains(internalToken)) {
            throw new IllegalStateException(
                    "gateway.internal-token (GATEWAY_INTERNAL_TOKEN) is set to a known-insecure default "
                            + "value ('local-dev-gateway-token'). Set a real, randomly-generated secret.");
        }
    }
}
