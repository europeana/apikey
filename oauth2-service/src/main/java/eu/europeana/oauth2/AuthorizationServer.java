package eu.europeana.oauth2;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

/**
 * OAuth2 authorization server.
 *
 * To issue a token run the following command:
 *    curl --user "simpleTestClient:simpleSecret" http://localhost:8888/oauth/token -d grant_type=client_credentials -d scope=read
 *  or
 *    curl --user "simpleTestClient:simpleSecret" http://localhost:8888/oauth/token -d grant_type=password -d username=user -d password=test
 *
 * Running this later will also show you the existing token for that client or user again.
 *
 * After you obtained a token you can refresh it using
 *    curl --user "simpleTestClient:simpleSecret" http://localhost:8888/oauth/token -d grant_type=refresh_token -d refresh_token=[insert_refresh_token]
 *
 * Created by Patrick Ehlert on 5-4-17.
 */
@SpringBootApplication
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class AuthorizationServer extends WebSecurityConfigurerAdapter {

    /**
     * Application main entry point, points to authorizationServer.yml config file
     * @param args
     */
    public static void main(String[] args) {
        new SpringApplicationBuilder(AuthorizationServer.class).properties("spring.config.name=authorizationServer").run(args);
    }

    @Configuration
    @EnableAuthorizationServer
    protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

        /**
         * A JSON Web Tokens (JWT) contains all user information encrypted in the token
         * @return a new default JWT access token converter
         */
        @Bean
        public JwtAccessTokenConverter jwtAccessTokenConverter() {
            return new JwtAccessTokenConverter();
        }

        /**
         * Enable the JWT tokens
         * @param endpoints
         * @throws Exception
         */
        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints.accessTokenConverter(jwtAccessTokenConverter());
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.inMemory()
                    .withClient("simpleTestClient")
                    .secret("simpleSecret")
                    .authorizedGrantTypes("authorization_code","client_credentials", "password", "refresh_token")
                    .authorities("ROLE_CLIENT")
                    .scopes("read", "write")
                    .and()
                    .withClient("unit_test")
                    .secret("test")
                    .authorizedGrantTypes("authorization_code","client_credentials", "password", "refresh_token")
                    .authorities("ROLE_CLIENT")
                    .scopes("read", "write");
        }

  }


}



