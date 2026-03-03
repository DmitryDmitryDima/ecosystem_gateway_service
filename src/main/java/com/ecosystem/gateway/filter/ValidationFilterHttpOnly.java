package com.ecosystem.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

/*
пишем версию фильтра для http only взаимодействия
 */
@Component
public class ValidationFilterHttpOnly extends AbstractGatewayFilterFactory<Object> {

    // реактивный клиент для взаимодействия с auth
    private final WebClient webClient;

    // адрес auth сервера (пока hardcoded)
    private final String authUrl = "http://localhost:8082";


    public ValidationFilterHttpOnly(WebClient.Builder webClientBuilder) {

        this.webClient = webClientBuilder.baseUrl(authUrl).build();



    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {

            System.out.println("accessed "+ exchange.getRequest().getPath());


            MultiValueMap<String, HttpCookie> cookies = exchange.getRequest().getCookies();

            HttpCookie accessToken = cookies.getFirst("accessToken");

            // пока запрещаем все запросы внутри системы кроме get для гостей
            if (!exchange.getRequest().getMethod().equals(HttpMethod.GET) && accessToken==null) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            // обрабатываем ситуации, где возможен просмотр чужого контента кем либо
            // - наша цель сообщить дальнейшим участникам цепочки uuid как viewer, так и target
            String targetUsername = exchange.getRequest().getQueryParams().getFirst("targetUsername");










            WebClient.RequestHeadersSpec<?> spec = webClient.get().uri("/validate")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer "+accessToken);
            // вставляем access token куки
            if (accessToken != null){
                spec.cookie("accessToken", accessToken.getValue());
            }
            if (targetUsername!=null){
                spec.header("targetUsername", targetUsername);
            }

            // если токен есть, перед нами авторизованный пользователь, проверяем его токен
            // токен не валиден - возвращаем 401
            // токен валиден - добавляем в headers полный security context
            return spec
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
                .header("targetuuid", (String) body.get("targetUUID"))
                .header("role", (String) body.get("role"))
                .header("username", (String) body.get("username"))
                .header("uuid", (String) body.get("uuid"))
                .build();
        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }
}
