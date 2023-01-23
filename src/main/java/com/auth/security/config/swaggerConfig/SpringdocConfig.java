package com.auth.security.config.swaggerConfig;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@OpenAPIDefinition
@Configuration
@SecurityScheme(
        name = "Bearer Authentication",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        scheme = "bearer"
)
public class SpringdocConfig {

    @Bean
    public OpenAPI baseOpenAPI(){
        OpenAPI openAPI = new OpenAPI();
        Info info = new Info();

        info.setTitle("Endpoint Documentation");
        info.setVersion("0.0.1");

        openAPI.info(info);

        return openAPI;
    }
}
