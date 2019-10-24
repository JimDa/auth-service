package com.example.auth.config;


import com.example.auth.CustomRedisTokenStore;
import com.example.auth.CustomTokenEnhancer;
import com.example.auth.multi.MultiAuthenticationTokenGranter;
import com.example.auth.service.IUserAccountService;
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
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableAuthorizationServer
public class AuthConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    @Qualifier("datasource")
    private DataSource dataSource;
    @Autowired
    private IUserAccountService iUserAccountService;

    private RedisConnectionFactory redisConnectionFactory;

    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
    }

    //客户端请求访问权限校验配置
    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
        //客户端账户密码以及accessToken,refreshToken的有效期配置在内存里
//        clients.inMemory()
//                .withClient("fooClientIdPassword").secret(bCryptPasswordEncoder.encode("secret"))
//                .redirectUris("http://localhost:8082/callback")
//                .authorizedGrantTypes("password", "refresh_token")
//                .scopes("create", "delete", "update", "read")
//                .and()
//                .withClient("user-service").secret("user-service-secret")
//                .authorizedGrantTypes("password", "refresh_token")
//                .scopes("create", "delete", "update", "read")
//                .accessTokenValiditySeconds(3600)
//                .refreshTokenValiditySeconds(2592000);

        //客户端账户密码以及accessToken,refreshToken的有效期配置在数据库里
        clients.jdbc(dataSource);
        /**一般而言，accessToken配置时间较短便于很快失效；refreshToken配置失效时间较长*/
    }


    //用户访问权限校验以及token存放配置
    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer conf) {
        conf
                .tokenStore(tokenStore(redisConnectionFactory))
                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST, HttpMethod.DELETE)
                .tokenEnhancer(tokenEnhancerChain())
                .tokenGranter(tokenGranter(conf))
//                .accessTokenConverter(accessTokenConverter())
                .authenticationManager(authenticationManager);
    }

    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer conf) {
        List<TokenGranter> granters = new ArrayList<>(Arrays.asList(conf.getTokenGranter()));
        granters.add(new MultiAuthenticationTokenGranter(authenticationManager, conf.getTokenServices(), conf.getClientDetailsService(), conf.getOAuth2RequestFactory(), iUserAccountService, defaultTokenServices()));
        return new CompositeTokenGranter(granters);
    }


    @Bean
    @Primary
    public DefaultTokenServices defaultTokenServices() {
        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore(redisConnectionFactory));
        defaultTokenServices.setSupportRefreshToken(true);
        defaultTokenServices.setReuseRefreshToken(false);
        defaultTokenServices.setTokenEnhancer(tokenEnhancerChain());
        return defaultTokenServices;
    }

    @Bean
    public TokenEnhancerChain tokenEnhancerChain() {
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(
                Arrays.asList(tokenEnhancer(), accessTokenConverter()));
        return tokenEnhancerChain;
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

    @Bean
    public TokenEnhancer tokenEnhancer() {
        return new CustomTokenEnhancer();
    }
}
