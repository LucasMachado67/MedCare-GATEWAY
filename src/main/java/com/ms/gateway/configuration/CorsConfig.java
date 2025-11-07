package com.ms.gateway.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.config.CorsRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;

@Configuration
public class CorsConfig {

    @Bean
    public WebFluxConfigurer corsConfigurer(){
        return new WebFluxConfigurer() {
            
            @Override
            public void addCorsMappings(CorsRegistry corsRegistry){
                corsRegistry.addMapping("/**")
                    .allowedOrigins("http://localhost:4200",
                        "http://localhost:8081",
                        "http://localhost:8080",
                        "http://localhost:8082")
                    .allowedMethods("GET", "POST", "PUT", "DELETE")
                    .allowedHeaders("*")
                    .allowCredentials(true);
            }

        };
    }
}
