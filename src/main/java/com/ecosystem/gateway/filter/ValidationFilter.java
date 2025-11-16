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

/*
Фильтр, защищающий зону /api приложения. Проверяет, содержит ли запрос access token, после обращения к auth серверу формирует secutity context
- если токена нет, помечает запрос как гостевой (headers - role), после чего внутри структуры api формируется только та часть информации, что может быть доступна гостям
- Если токен есть, и он действителен - формируется security context в headers (username, role, user uuid).
Помним, что все данные в системе формируются вокруг user uuid
- Если токен есть, но он просрочен - возвращается 401, после чего фронтенд делает запрос на refresh
 */

@Component
public class ValidationFilter extends AbstractGatewayFilterFactory<Object> {

    // реактивный клиент для взаимодействия с auth
    private final WebClient webClient;

    // адрес auth сервера (пока hardcoded)
    private final String authUrl = "http://localhost:8082";


    public ValidationFilter(WebClient.Builder webClientBuilder) {

        this.webClient = webClientBuilder.baseUrl(authUrl).build();



    }



    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {

            // пытаемся извлечь авторизационный токен типа bearer (с англ - предъявитель)
            String token =
                    exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);


            // токена нет - перед нами гость. Вносим инфу (mutate) об этом в security context, после чего пробрасываем запрос дальше
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
                    // переводим тело ответа в читаемый вид - Map<String, String>
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                    // сценарий 1 - токен валиден, получен контекст - добавляем headers
                    .flatMap(body->upgradeRequest(body, exchange, chain))
                    // сценарий 2 - ошибка, токен не валиден, возвращаем 401
                    .onErrorResume(exception->{
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });

        };
    }

    // добавляем для запроса к api security context при успешной валидации токена
    private Mono<Void> upgradeRequest(Map<String, Object> body, ServerWebExchange exchange, GatewayFilterChain chain){
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("role", (String) body.get("role"))
                .header("username", (String) body.get("username"))
                .header("uuid", (String) body.get("uuid"))
                .build();
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }






}
