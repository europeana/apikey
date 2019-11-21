package eu.europeana.apikey.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.Collections;

/**
 * Configures swagger on all requests. Swagger Json file is availabe at /v2/api-docs
 * @author Patrick Ehlert
 * Created on 26-01-2018
 */
@Configuration
@EnableSwagger2
public class SwaggerConfig {

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(RequestHandlerSelectors.basePackage("eu.europeana.apikey"))
                .paths(PathSelectors.any())
                .build();
    }

    private ApiInfo apiInfo() {
        return new ApiInfo(
                "Apikey Service",
                "Europeana API-key service",
                null,
                null,
                new Contact("APIs team", "www.europeana.eu", "api@europeana.eu"),
                "EUPL 1.2", "API license URL", Collections.emptyList());
    }
}
