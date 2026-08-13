package com.selflearning.gatewayservice.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(AuthGlobalFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String X_USER_ID = "X-User-Id";
    private static final String X_USERNAME = "X-Username";
    private static final String X_SESSION_ID = "X-Session-Id";
    private static final String X_TOKEN_ID = "X-Token-Id";
    private static final String X_GATEWAY_TOKEN = "X-Gateway-Token";
    private static final TypeReference<ApiResponse<TokenValidateResponse>> TOKEN_VALIDATE_RESPONSE_TYPE =
            new TypeReference<>() {
            };

    private final WebClient.Builder webClientBuilder;
    private final AuthProperties authProperties;
    private final ObjectMapper objectMapper;
    private final String gatewayInternalToken;

    public AuthGlobalFilter(
            WebClient.Builder webClientBuilder,
            AuthProperties authProperties,
            ObjectMapper objectMapper,
            @Value("${gateway.internal-token}") String gatewayInternalToken) {
        this.webClientBuilder = webClientBuilder;
        this.authProperties = authProperties;
        this.objectMapper = objectMapper;
        this.gatewayInternalToken = gatewayInternalToken;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (isWhitelisted(path)) {
            return chain.filter(exchange);
        }

        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return writeUnauthorized(exchange, "missing or malformed Authorization header");
        }

        String accessToken = authorization.substring(BEARER_PREFIX.length()).trim();
        if (accessToken.isBlank()) {
            return writeUnauthorized(exchange, "missing or malformed Authorization header");
        }

        // 注意：错误处理只能包在 validateToken(...) 这一段上，不能包到 flatMap 里的
        // chain.filter(...)（那是转发给下游业务服务的真实请求）。之前这两个 onErrorResume
        // 是接在整条链最后的，Reactor 里这样写会把 chain.filter(...) 抛出的任何异常也一并
        // 吞掉——包括下游服务没启动/负载均衡找不到实例时抛出的 NotFoundException——统统被
        // 错误地包装成 401 "token validation failed" 返回给前端，即便 token 本身完全有效。
        // 前端因此把"后端服务不可用"误判成"登录过期"，尝试刷新 token 再重试一次，重试同样
        // 因为服务没启动而失败，最终把用户直接踢回登录页——这是 2026-08-11 排查一次"登录后
        // 又跳回登录页"用户反馈时定位到的真实根因，而不是 token/session 机制本身的问题。
        return validateToken(accessToken, authorization)
                .onErrorMap(ex -> !(ex instanceof TokenValidationException), ex -> new TokenValidationException(ex.toString()))
                .flatMap(token -> {
                    if (token.userId() == null || token.username() == null || token.tokenId() == null) {
                        return writeUnauthorized(exchange, "token validation failed");
                    }
                    ServerHttpRequest trustedRequest = buildTrustedRequest(exchange.getRequest(), token);
                    return chain.filter(exchange.mutate().request(trustedRequest).build());
                })
                .onErrorResume(TokenValidationException.class, ex -> {
                    log.warn("Token validation failed: {}", ex.getMessage());
                    return writeUnauthorized(exchange, "token validation failed");
                });
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    private Mono<TokenValidateResponse> validateToken(String token, String authorization) {
        return webClientBuilder.build()
                .post()
                .uri(authProperties.tokenValidationUri())
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new TokenValidateRequest(token))
                .exchangeToMono(this::handleTokenValidationResponse)
                .timeout(authProperties.tokenValidationTimeout());
    }

    private Mono<TokenValidateResponse> handleTokenValidationResponse(ClientResponse response) {
        int httpStatus = response.statusCode().value();
        return response.bodyToMono(String.class)
                .defaultIfEmpty("")
                .flatMap(body -> {
                    ApiResponse<TokenValidateResponse> apiResponse = parseTokenValidationResponse(httpStatus, body);
                    if (httpStatus < 200 || httpStatus >= 300) {
                        return Mono.error(new TokenValidationException(formatAuthServiceError(httpStatus, apiResponse)));
                    }
                    if (apiResponse.code() != 200) {
                        return Mono.error(new TokenValidationException(formatAuthServiceError(httpStatus, apiResponse)));
                    }
                    TokenValidateResponse data = apiResponse.data();
                    if (data == null) {
                        return Mono.error(new TokenValidationException("auth-service returned empty token validation data"));
                    }
                    if (!data.valid()) {
                        return Mono.error(new TokenValidationException("auth-service returned invalid token"));
                    }
                    return Mono.just(data);
                });
    }

    private ApiResponse<TokenValidateResponse> parseTokenValidationResponse(int httpStatus, String body) {
        if (body == null || body.isBlank()) {
            throw new TokenValidationException("auth-service returned empty response, httpStatus=" + httpStatus);
        }
        try {
            return objectMapper.readValue(body, TOKEN_VALIDATE_RESPONSE_TYPE);
        } catch (JsonProcessingException ex) {
            throw new TokenValidationException("auth-service returned non-standard response, httpStatus=" + httpStatus);
        }
    }

    private String formatAuthServiceError(int httpStatus, ApiResponse<TokenValidateResponse> response) {
        return "auth-service returned httpStatus=%d, code=%d, message=%s"
                .formatted(httpStatus, response.code(), response.message());
    }

    private ServerHttpRequest buildTrustedRequest(ServerHttpRequest request, TokenValidateResponse token) {
        return request.mutate()
                .headers(headers -> {
                    headers.remove(X_USER_ID);
                    headers.remove(X_USERNAME);
                    headers.remove(X_SESSION_ID);
                    headers.remove(X_TOKEN_ID);
                    headers.remove(X_GATEWAY_TOKEN);
                    headers.set(X_USER_ID, token.userId().toString());
                    headers.set(X_USERNAME, token.username());
                    if (token.sessionId() != null && !token.sessionId().isBlank()) {
                        headers.set(X_SESSION_ID, token.sessionId());
                    }
                    headers.set(X_TOKEN_ID, token.tokenId());
                    headers.set(X_GATEWAY_TOKEN, gatewayInternalToken);
                })
                .build();
    }

    private boolean isWhitelisted(String path) {
        return authProperties.whitelistPaths().stream().anyMatch(pattern -> matches(pattern, path));
    }

    private boolean matches(String pattern, String path) {
        if (pattern.endsWith("/**")) {
            String prefix = pattern.substring(0, pattern.length() - 3);
            return path.equals(prefix) || path.startsWith(prefix + "/");
        }
        return path.equals(pattern);
    }

    private Mono<Void> writeUnauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        if (response.isCommitted()) {
            return Mono.empty();
        }
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] body = toJsonBytes(ApiResponse.error(401, message));
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }

    private byte[] toJsonBytes(ApiResponse<Void> response) {
        try {
            return objectMapper.writeValueAsBytes(response);
        } catch (JsonProcessingException ignored) {
            return "{\"code\":401,\"message\":\"token validation failed\",\"data\":null}".getBytes(StandardCharsets.UTF_8);
        }
    }

    private static class TokenValidationException extends RuntimeException {

        TokenValidationException(String message) {
            super(message);
        }
    }
}
