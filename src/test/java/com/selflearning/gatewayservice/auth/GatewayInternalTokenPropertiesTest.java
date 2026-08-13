package com.selflearning.gatewayservice.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Verifies {@link GatewayInternalTokenProperties}'s two enforcement layers independently:
 * <ul>
 *   <li>Bean Validation constraints ({@code @NotBlank}/{@code @Size}) — exercised directly against a
 *   {@link Validator}, the same mechanism Spring invokes when binding {@code @ConfigurationProperties} at
 *   startup, without needing to boot a Spring context (this project's {@code @SpringBootTest} contexts
 *   currently fail to load for an unrelated pre-existing reason — see other batches' test Javadocs).</li>
 *   <li>The known-weak-value rejection, which lives in the record's compact constructor and therefore
 *   always runs regardless of how the record is constructed (validation framework or plain {@code new}).</li>
 * </ul>
 */
class GatewayInternalTokenPropertiesTest {

    private static final String VALID_TOKEN = "a-randomly-generated-secret-that-is-plenty-long-enough";

    private static ValidatorFactory validatorFactory;
    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @AfterAll
    static void tearDownValidator() {
        validatorFactory.close();
    }

    @Test
    void acceptsAStrongEnoughToken() {
        GatewayInternalTokenProperties properties = new GatewayInternalTokenProperties(VALID_TOKEN);
        Set<ConstraintViolation<GatewayInternalTokenProperties>> violations = validator.validate(properties);
        assertThat(violations).isEmpty();
    }

    @Test
    void rejectsBlankToken() {
        Set<ConstraintViolation<GatewayInternalTokenProperties>> violations =
                validator.validate(new GatewayInternalTokenProperties(""));
        assertThat(violations).isNotEmpty();
    }

    @Test
    void rejectsTokenShorterThan32Characters() {
        Set<ConstraintViolation<GatewayInternalTokenProperties>> violations =
                validator.validate(new GatewayInternalTokenProperties("too-short-for-a-shared-secret"));
        assertThat(violations).isNotEmpty();
    }

    // 明确弱值拒绝规则：这条检查在 record 的 compact constructor 里，不依赖 Bean Validation
    // 框架——直接 new（不经过 jakarta.validation.Validator）也会触发，证明它是独立于长度校验的
    // 第二道防线，不是靠"这个弱值恰好也太短"侥幸挡住的。
    @Test
    void rejectsKnownInsecureDefaultValueOnConstruction() {
        assertThatThrownBy(() -> new GatewayInternalTokenProperties("local-dev-gateway-token"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("local-dev-gateway-token");
    }
}
