package eu.europeana.apikey.config;

import eu.europeana.apikey.keycloak.CustomKeycloakAuthenticationProvider;
import org.springframework.beans.factory.annotation.Value;
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

    @Value("${europeana.apikey.ssl:true}")
    private boolean useSsl;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        if (useSsl){
            http.authorizeRequests()
                  //  .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                    .antMatchers(HttpMethod.OPTIONS, "/apikey/captcha").permitAll()
                    .antMatchers(HttpMethod.POST, "/apikey/captcha").permitAll()
                    .antMatchers(HttpMethod.POST, "/apikey/validate").permitAll()
                    .antMatchers(HttpMethod.GET, "/actuator/**").permitAll()
                    // for Swagger UI
                    .antMatchers(HttpMethod.GET, "/v3/**").permitAll()
                    .antMatchers(HttpMethod.GET, "/console").permitAll()
                    .antMatchers(HttpMethod.GET, "/swagger-ui/**").permitAll()
                  //  .antMatchers(HttpMethod.GET, "/googlea6365b758a9850fb.html").permitAll()
                    .anyRequest().authenticated().and()
                .httpBasic().and()
                .requiresChannel().anyRequest().requiresSecure().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .csrf().disable();
        } else {
            http.authorizeRequests()
                   // .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                    .antMatchers(HttpMethod.OPTIONS, "/apikey/captcha").permitAll()
                    .antMatchers(HttpMethod.POST, "/apikey/captcha").permitAll()
                    .antMatchers(HttpMethod.POST, "/apikey/validate").permitAll()
                    .antMatchers(HttpMethod.GET, "/actuator/**").permitAll()
                    // for Swagger UI
                    .antMatchers(HttpMethod.GET, "/v3/**").permitAll()
                    .antMatchers(HttpMethod.GET, "/console").permitAll()
                    .antMatchers(HttpMethod.GET, "/swagger-ui/**").permitAll()
                  //  .antMatchers(HttpMethod.GET, "/googlea6365b758a9850fb.html").permitAll()
                    .anyRequest().authenticated().and()
                .httpBasic().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .csrf().disable();
        }
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
