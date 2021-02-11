package eu.europeana.apikey.config;

import eu.europeana.apikey.keycloak.CustomEntryPoint;
import eu.europeana.apikey.keycloak.CustomKeycloakAuthenticationProvider;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // https://stackoverflow.com/questions/46870411/how-to-require-ssl-in-some-environments-using-spring-boot-2-0-0-m4
//                .requestMatchers( r -> r.getHeader("X-Forwarded-Proto") != null).requiresSecure().and()
            .authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS, "/apikey/captcha").permitAll()
                .antMatchers(HttpMethod.POST, "/apikey/captcha").permitAll()
                .antMatchers(HttpMethod.POST, "/apikey/validate").permitAll()
                .anyRequest().authenticated().and()
            .httpBasic().and()
            .requiresChannel().anyRequest().requiresSecure().and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .csrf().disable()
            .exceptionHandling().authenticationEntryPoint(new CustomEntryPoint());
    }

    @Configuration
    static class WebSecurityConfiguration extends GlobalAuthenticationConfigurerAdapter {

        @Override
        public void init(AuthenticationManagerBuilder auth) {
            auth.authenticationProvider(this.authenticationProvider);
        }

        private final CustomKeycloakAuthenticationProvider authenticationProvider;

        public WebSecurityConfiguration(CustomKeycloakAuthenticationProvider authenticationProvider) {
            this.authenticationProvider = authenticationProvider;
        }
    }

}
