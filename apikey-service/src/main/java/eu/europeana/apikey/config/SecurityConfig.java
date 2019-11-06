package eu.europeana.apikey.config;

import eu.europeana.apikey.keycloak.CustomKeycloakAuthenticationProvider;
import eu.europeana.apikey.keycloak.KeycloakManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http          .authorizeRequests().antMatchers(HttpMethod.OPTIONS, "/apikey/captcha").permitAll()
                .and().authorizeRequests().antMatchers(HttpMethod.POST, "/apikey/captcha").permitAll()
                .and().authorizeRequests().antMatchers(HttpMethod.POST, "/apikey/validate").permitAll()
                .and().authorizeRequests().antMatchers(HttpMethod.POST, "/apikey", "/apikey/").authenticated()
                .and().authorizeRequests().antMatchers("/apikey/**").authenticated()
                .and().httpBasic()
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().csrf().disable();
    }

    @Configuration
    class WebSecurityConfiguration extends GlobalAuthenticationConfigurerAdapter {

        @Override
        public void init(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(getCustomKeycloakAuthenticationProvider());
        }

        @Bean
        public CustomKeycloakAuthenticationProvider getCustomKeycloakAuthenticationProvider() {
            return new CustomKeycloakAuthenticationProvider(getKeycloakManager());
        }

        @Bean
        public KeycloakManager getKeycloakManager() {
            return new KeycloakManager();
        }
    }

}
