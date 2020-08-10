package eu.europeana.apikey.config;

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
        http.requiresChannel().requestMatchers(r -> r.getHeader("X-Forwarded-Proto") != null)
            .requiresSecure().and()
            .authorizeRequests().antMatchers(HttpMethod.OPTIONS, "/apikey/captcha").permitAll().and()
            .authorizeRequests().antMatchers(HttpMethod.POST, "/apikey/captcha").permitAll().and()
            .authorizeRequests().antMatchers(HttpMethod.POST, "/apikey/validate").permitAll().and()
            .authorizeRequests().antMatchers(HttpMethod.POST, "/apikey", "/apikey/").authenticated().and()
            .authorizeRequests().antMatchers("/apikey/**").authenticated().and()
            .authorizeRequests().antMatchers(HttpMethod.OPTIONS, "/apikeyclient/captcha").permitAll().and()
            .authorizeRequests().antMatchers(HttpMethod.POST, "/apikeyclient/captcha").permitAll().and()
            .authorizeRequests().antMatchers(HttpMethod.POST, "/apikeyclient", "/apikeyclient/").authenticated().and()
            .authorizeRequests().antMatchers("/apikeyclient/**").authenticated().and()
            .httpBasic().and()
            .requiresChannel().anyRequest().requiresSecure().and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .csrf().disable();
    }

    @Configuration
    static class WebSecurityConfiguration extends GlobalAuthenticationConfigurerAdapter {

        @Override
        public void init(AuthenticationManagerBuilder auth) {
            auth.authenticationProvider(this.authenticationProvider);
        }

        private CustomKeycloakAuthenticationProvider authenticationProvider;

        public WebSecurityConfiguration(CustomKeycloakAuthenticationProvider authenticationProvider) {
            this.authenticationProvider = authenticationProvider;
        }
    }

}
