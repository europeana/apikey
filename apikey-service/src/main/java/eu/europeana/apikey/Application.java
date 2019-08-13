/*
 * Copyright 2007-2017 The Europeana Foundation
 *
 *  Licenced under the EUPL, Version 1.1 (the "Licence") and subsequent versions as approved
 *  by the European Commission;
 *  You may not use this work except in compliance with the Licence.
 *
 *  You may obtain a copy of the Licence at:
 *  http://joinup.ec.europa.eu/software/page/eupl
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under
 *  the Licence is distributed on an "AS IS" basis, without warranties or conditions of
 *  any kind, either express or implied.
 *  See the Licence for the specific language governing permissions and limitations under
 *  the Licence.
 */


/**
 * Created by luthien on 18/04/2017.
 */

package eu.europeana.apikey;

import eu.europeana.apikey.keycloak.CustomKeycloakAuthenticationProvider;
import eu.europeana.apikey.keycloak.KeycloakManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.HttpMethod;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@PropertySource(value = "classpath:build.properties", ignoreResourceNotFound = true)
@SpringBootApplication
@ComponentScan("eu.europeana.apikey")
public class Application extends SpringBootServletInitializer {

    public static void main(String[] args) {
        SpringApplicationBuilder builder = new SpringApplicationBuilder();
        builder.sources(Application.class).run(args);
    }

    @Component
    public static class SampleDataPopulator implements CommandLineRunner {

        @Override
        public void run(String... args) throws Exception {
        }
    }
}
@Configuration
class WebSecurityConfiguration extends GlobalAuthenticationConfigurerAdapter {

    @Override
    public void init(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(getAuthenticationProvider());
    }

    @Bean
    public CustomKeycloakAuthenticationProvider getAuthenticationProvider() {
        return new CustomKeycloakAuthenticationProvider(getKeycloakManager());
    }

    @Bean
    public KeycloakManager getKeycloakManager() {
        return new KeycloakManager();
    }
}

@EnableWebSecurity
@Configuration
class ApiSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http    .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/apikey/**", "/info").permitAll()
                .antMatchers(HttpMethod.POST, "/apikey").authenticated()
                .and().authorizeRequests().antMatchers(HttpMethod.POST, "/apikey/**").permitAll()
                .and().httpBasic()
                .and().csrf().disable();
    }
}

@Component
@ConfigurationProperties("europeanamail")
class EuropeanaMailProperties {
    private String sentFrom;

    public String getSentFrom() {
        return sentFrom;
    }
    public void setSentFrom(String sentFrom) {
        this.sentFrom = sentFrom;
    }
}

@Configuration
@EnableWebMvc
class MailConfig extends WebMvcConfigurerAdapter {
    @Autowired
    private EuropeanaMailProperties europeanaMailProperties;
    @Bean
    public SimpleMailMessage apikeyCreatedMail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setText("Dear %s %s,%n%nThank you for registering for the Europeana API." +
                "%n%n" +
                "These are your Europeana API keys: %n===========================%n" +
                "API key: \t\t%s %nPrivate key: \t%s %n===========================%n" +
                "%n%n" +
                "The private key is used for specific API methods that require additional user authentication while " +
                "the public key must be used by all others, see https://pro.europeana.eu/resources/apis/intro#access." +
                "%n%n" +
                "Please keep a safe record of these keys and do not share them with third parties or expose it in user " +
                "interfaces or in markup, as the " +
                "API keys are confidential and are for use by the client or user only." +
                "%n%n" +
                "Our technical documentation for all APIs is available at https://pro.europeana.eu/resources/apis which " +
                "includes an API console for testing and community developed libraries for a variety of programming languages." +
                "%n%n" +
                "Please join us in the Europeana API Forum (https://groups.google.com/forum/?pli=1#!forum/europeanaapi) " +
                "- to ask questions to us and other developers and to give us your feedback on our API. " +
                "You can also contact us directly by mailing api@europeana.eu " +
                "and we would be especially grateful if you would let us know about your implementation so that we can " +
                "feature it in our application gallery on Europeana Pro - https://pro.europeana.eu/resources/apps." +
                "%n%n" +
                "Best regards," +
                "%n" +
                "The Europeana API Team");
        message.setFrom(europeanaMailProperties.getSentFrom());
        return message;
    }
}
