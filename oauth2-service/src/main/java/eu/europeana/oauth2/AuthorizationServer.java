package eu.europeana.oauth2;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

/**
 * Created by Patrick Ehlert on 5-4-17.
 */
@SpringBootApplication
@EnableAuthorizationServer
public class AuthorizationServer {

    public static void main(String[] args) {
        new SpringApplicationBuilder(AuthorizationServer.class).properties("spring.config.name=authorizationServer").run(args);
    }
}



