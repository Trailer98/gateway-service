package com.selflearning.gatewayservice.config;

import com.selflearning.gatewayservice.auth.AuthProperties;
import com.selflearning.gatewayservice.auth.GatewayInternalTokenProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
@EnableConfigurationProperties({AuthProperties.class, GatewayInternalTokenProperties.class})
public class WebClientConfig {

    @Bean
    @LoadBalanced
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }
}
