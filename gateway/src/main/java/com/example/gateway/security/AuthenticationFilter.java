package com.example.gateway.security;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private RouterValidator validator;
    @Autowired
    private JwtUtil jwtUtil;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (validator.isSecured.test(exchange.getRequest())) {
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    return onError(exchange, "Falta token de autorización", HttpStatus.UNAUTHORIZED);
                }

                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                } else {
                    return onError(exchange, "Token inválido", HttpStatus.UNAUTHORIZED);
                }

                try {
                    jwtUtil.validateToken(authHeader);
                    Claims claims = jwtUtil.getClaims(authHeader);
                    String rol = claims.get("rol", String.class);
                    String requestPath = exchange.getRequest().getURI().getPath();
                    String method = exchange.getRequest().getMethod().name();

                    if (!tienePermisos(rol, requestPath, method)) {
                        return onError(exchange, "Acceso denegado", HttpStatus.FORBIDDEN);
                    }

                    // Pasar ID al microservicio
                    exchange.getRequest().mutate()
                            .header("X-User-Id", String.valueOf(claims.get("id")))
                            .build();

                } catch (Exception e) {
                    return onError(exchange, "Token no válido", HttpStatus.FORBIDDEN);
                }
            }
            return chain.filter(exchange);
        });
    }

    private boolean tienePermisos(String rol, String path, String method) {
        if ("ADMIN".equals(rol)) return true;
        if ("USER".equals(rol)) {
            if (path.contains("/monopatines/cercanos") && method.equals("GET")) return true;
            if (path.contains("/viajes/uso-por-cuenta") && method.equals("GET")) return true;
            if (path.contains("/viajes") && method.equals("POST")) return true;
            if (path.contains("/cuentas") && method.equals("GET")) return true;
            // Bloqueos explícitos para usuarios normales
            if (path.contains("/monopatines/uso")) return false;
            if (path.contains("/tarifas") && method.equals("PUT")) return false;
            if (path.contains("/facturas/total")) return false;
            if (path.contains("/usuarios/uso-frecuente")) return false;

            return true; // Resto de lecturas permitidas por defecto
        }
        return false;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse().setComplete();
    }

    public static class Config {}
}