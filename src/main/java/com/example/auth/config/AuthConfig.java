package com.example.auth.config;


import com.example.auth.CustomRedisTokenStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

@Configuration
@EnableAuthorizationServer
public class AuthConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    private RedisConnectionFactory redisConnectionFactory;

    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception { // @formatter:off
        clients.inMemory()
                .withClient("fooClientIdPassword").secret(bCryptPasswordEncoder.encode("secret"))
//                .redirectUris("http://localhost:8081/callback")
                /* 1 */.authorizedGrantTypes("password", "refresh_token")
                /* 2 */.scopes("create", "delete", "update", "read")
                .and()
                .withClient("user-service").secret("user-service-secret")
                /* 1 */.authorizedGrantTypes("password", "refresh_token")
                /* 2 */.scopes("create", "delete", "update", "read")
                .accessTokenValiditySeconds(3600)
                // store accessToken for 1 hour so that it expires quickly
                /* 3 */.refreshTokenValiditySeconds(2592000);
        // store refreshToken for 30 days
    } // @formatter:on

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer conf) { // @formatter:off
        conf
                .tokenStore(tokenStore(redisConnectionFactory))
                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST, HttpMethod.DELETE)
                .accessTokenConverter(accessTokenConverter())
                .authenticationManager(authenticationManager);
    } // @formatter:on

    @Bean
    @Primary
    public DefaultTokenServices defaultTokenServices() {
        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore(redisConnectionFactory));
        /* 4 */
        defaultTokenServices.setSupportRefreshToken(true);
        defaultTokenServices.setReuseRefreshToken(false);
        defaultTokenServices.setTokenEnhancer(accessTokenConverter());
        return defaultTokenServices;
    }

    @Bean
    public TokenStore tokenStore(RedisConnectionFactory redisConnectionFactory) {
        return new CustomRedisTokenStore(redisConnectionFactory);
    }

    @Bean(name = "jwtAccessTokenConverter")
    public JwtAccessTokenConverter accessTokenConverter() {
        final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("123");
        return converter;
    }
}
