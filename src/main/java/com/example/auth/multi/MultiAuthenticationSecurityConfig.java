package com.example.auth.multi;

import com.example.auth.service.IUserAccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class MultiAuthenticationSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    @Autowired
    private StringRedisTemplate stringRedisTemplate;
    @Autowired
    private IUserAccountService iUserAccountService;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        MultiAuthenticationFilter multiAuthenticationFilter = new MultiAuthenticationFilter();
        multiAuthenticationFilter.setAuthenticationManager(httpSecurity.getSharedObject(AuthenticationManager.class));

        MultiAuthenticationProvider multiAuthenticationProvider = new MultiAuthenticationProvider();
        multiAuthenticationProvider.setIUserAccountService(iUserAccountService);
        multiAuthenticationProvider.setStringRedisTemplate(stringRedisTemplate);
        multiAuthenticationProvider.setBCryptPasswordEncoder(bCryptPasswordEncoder);
        httpSecurity.authenticationProvider(multiAuthenticationProvider)
                .addFilterBefore(multiAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
