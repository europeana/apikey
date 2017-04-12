package eu.europeana.oauth2;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * Very simple test client application that connects to our oauth2 server using Spring-Boot
 * Start this application and go to http://localhost:8080
 * To avoid auto-login from previously stored cookies it's recommended to do this in a private tab in your browser.
 *
 * Created by Patrick Ehlert on 5-4-17.
 */
@SpringBootApplication
@EnableAutoConfiguration
@Configuration
@EnableOAuth2Sso
@RestController
public class SimpleTestClient {

    /**
     * @param user
     * @return user name of the logged-in user
     */
    @RequestMapping("/")
    public String userName(Principal user) {
        return "Logged in as: " +user.getName();
    }

    /**
     * Application main entry point, loads config from simpleTestClient.yml
     * @param args
     */
    public static void main(String[] args) {
        new SpringApplicationBuilder(SimpleTestClient.class).properties("spring.config.name=simpleTestClient").run(args);
    }
}
