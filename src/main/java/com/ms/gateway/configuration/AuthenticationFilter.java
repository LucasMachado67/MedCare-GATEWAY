package com.ms.gateway.configuration;

import java.util.List;
import java.util.function.Predicate;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import reactor.core.publisher.Mono;
/*
GlobalFilter - Interface principal do Spring Cloud Gateway que permite a interceptação de todas as requisições
que passam pelo Gateway. O método filter é o ponto de entrada da lógica.
 *
 *
Ordered - Define a ordem de execução deste filtro em relação aos outros filtros globais e de rota do Gateway.
 */

@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {
    /*
     A chave secreta (secret key) usada para assinar e validar os 'tokens' JWT.
     É injetada a partir do arquivo de configuração (application.yml ou application.properties).
    */
    private final String secret;

    //Construtor
    public AuthenticationFilter(@Value("${api.security.token.secret}") String secret) {
        this.secret = secret;
    }

    /*
     Lista de URIs que não exigem autenticação (não precisam de um 'token' JWT).
     Qualquer rota que comece com um desses prefixos será liberada imediatamente para ser roteada ao microservice.
    */
    public static final List<String> openEndpoints = List.of(
            "/auth/login",
            "/auth/signup",
            "/auth/validate",
            "/auth/all"
//            "/medic",
//            "/patient/create",
//            "/person/create",
//            "/patient"
    );
    /**
     * Define a lógica de filtragem para cada requisição.
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // 1. Verificar Rotas Abertas
        // Cria um Predicate para checar se o caminho da requisição começa com algum dos endpoints abertos.
        Predicate<String> isPathOpen = p -> openEndpoints.stream()
                .anyMatch(path::startsWith);

        if (isPathOpen.test(path)) {
            System.out.println("Rota aberta: " + path + ". Prosseguindo sem validação de token.");
            // Se a rota for pública, prossegue imediatamente na cadeia de filtros.
            return chain.filter(exchange);
        }

        // 2. Lógica de Validação para Rotas Protegidas

        // Verificar a presença do cabeçalho de Autorização
        if (!request.getHeaders().containsKey("Authorization")) {
            // Se o header estiver ausente, retorna 401 UNAUTHORIZED.
            return this.onError(exchange, "Authorization header ausente");
        }

        String authHeader = request.getHeaders().getOrEmpty("Authorization").get(0);

        // Verificar o formato (deve ser "Bearer <token>")
        if (!authHeader.startsWith("Bearer ")) {
            // Se o formato for inválido, retorna 401 UNAUTHORIZED.
            return this.onError(exchange, "Formato de token inválido (Esperado: Bearer <token>)");
        }

        String token = authHeader.replace("Bearer ", "");

        // 3. Validar e Processar o Token
        try {
            // Tenta validar o 'token'. Se falhar, uma exceção é lançada.
            Claims claims = getClaimsFromToken(token);
            Boolean mustChange = claims.get("mustChangePassword", Boolean.class);

            // Adicione este log para sabermos exatamente o que o Gateway está lendo
            System.out.println("Path atual: " + path + " | MustChange: " + mustChange);

            // Melhore a condição: Se for update-password, SEMPRE deixa passar
            boolean isUpdatePasswordPath = path.contains("update-password");

            if (mustChange != null && mustChange && !isUpdatePasswordPath) {
                System.out.println("Bloqueio de segurança: Redirecionando para troca de senha.");
                return this.onError(exchange, "PASSWORD_CHANGE_REQUIRED");
            }
            // Isso evita que o microservice precise decodificar o 'token' novamente.
            exchange.getRequest().mutate()
                    .header("X-User-Id", claims.getSubject()) // Adiciona o Subject (geralmente o ID do usuário)
                    .build();

        } catch (Exception e) {
            System.err.println("Erro na validação do JWT: " + e.getMessage());
            return this.onError(exchange, "Token JWT inválido ou expirado");
        }

        // 4. Se chegou até aqui, o token é válido. Prosseguir.
        System.out.println("Chegou no token");
        return chain.filter(exchange);
    }

    /**
     * Método para tratar erros e retornar a resposta ao cliente de forma reativa.
     *
     * @param exchange O contexto da requisição/resposta.
     * @param err      A mensagem de erro (apenas para 'log' interno).
     * @return Um Mono<Void> que completa a resposta.
     */
    private Mono<Void> onError(ServerWebExchange exchange, String err) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        // Opcional: Adicionar um corpo de erro ou log detalhado aqui
        return response.setComplete();
    }

    /**
     * Método para obter e validar os Claims (corpo) do Token.
     * Usa a chave secreta injetada para verificar a assinatura.
     * @param token O token JWT no formato String.
     * @return O objeto Claims contendo o corpo do token.
     * @throws io.jsonwebtoken.JwtException Se a validação falhar.
     */
    private Claims getClaimsFromToken(String token) {
        try {
        // Especificar o Charset (StandardCharsets.UTF_8)
        // Tenta criar a chave HMAC a partir dos bytes da sua string secreta (UTF-8)
        java.security.Key signingKey = Keys.hmacShaKeyFor(secret.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return Jwts.parserBuilder()
                .setSigningKey(signingKey) // Mudar aqui
                .build()
                .parseClaimsJws(token)
                .getBody();
    } catch (Exception e) {
        // Relançar exceção mais específica, ou tratar
        throw new RuntimeException("Falha na de codificação JWT", e);
    }
    }

    /**
     * Define a ordem de execução do filtro na cadeia de filtros do Gateway.
     * @return Um valor inteiro que define a prioridade.
     */
    @Override
    public int getOrder() {
        // Retornar um valor alto e negativo garante que este filtro execute primeiro.
        // O valor padrão para GlobalFilters é 0. Um valor como -1 ou -10 é suficiente.
        // -100 é um valor seguro para ser um dos primeiros.
        return -100;
    }
}

