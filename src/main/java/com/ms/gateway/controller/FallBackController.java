// package com.ms.gateway.controller;

// import org.springframework.web.bind.annotation.RestController;

// import reactor.core.publisher.Mono;

// import org.springframework.web.bind.annotation.RequestMapping;


// @RestController
// @RequestMapping("fallback")
// public class FallBackController {

//     @RequestMapping("/auth")
//     public Mono<String> authFallback() {
//         return Mono.just("Serviço de autenticação está temporariamente indisponível.");
//     }

//     @RequestMapping("/appointments")
//     public Mono<String> appointmentsFallback() {
//         return Mono.just("Serviço de agendamento está temporariamente indisponível.");
//     }

//     @RequestMapping("/entity")
//     public Mono<String> entityFallback() {
//         return Mono.just("Serviço de entidade está temporariamente indisponível.");
//     }
    
// }
