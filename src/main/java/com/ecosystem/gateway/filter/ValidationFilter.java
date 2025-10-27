package com.ecosystem.gateway.filter;


import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

@Component
public class ValidationFilter extends AbstractGatewayFilterFactory<Object> {

    private final WebClient webClient;
    private final String authUrl = "http://localhost:8082";


    public ValidationFilter(WebClient.Builder webClientBuilder) {

        this.webClient = webClientBuilder.baseUrl(authUrl).build();



    }



    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {

            String token =
                    exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            // токена нет - перед нами гость. Вносим инфу об этом в security context
            if(token == null || !token.startsWith("Bearer ") || token.length() <= 7) {

                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                        .header("role", "GUEST")
                        .build();

                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            }

            // если токен есть, перед нами авторизованный пользователь, проверяем его токен
            // токен не валиден - возвращаем 401
            // токен валиден - добавляем в headers полный security context
            return webClient.get()
                    .uri("/validate")
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .flatMap(body->upgradeRequest(body, exchange, chain))
                    .onErrorResume(exception->{
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });

        };
    }

    // добавляем security context при успешной валидации токена
    private Mono<Void> upgradeRequest(Map<String, Object> body, ServerWebExchange exchange, GatewayFilterChain chain){
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("role", (String) body.get("role"))
                .header("username", (String) body.get("username"))
                .header("uuid", (String) body.get("uuid"))
                .build();
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }






}
