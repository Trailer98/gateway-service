package com.selflearning.gatewayservice.auth;

public record ApiResponse<T>(
        int code,
        String message,
        T data
) {

    public static ApiResponse<Void> error(int code, String message) {
        return new ApiResponse<>(code, message, null);
    }
}
