package com.example.auth.config;

import com.example.auth.service.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    @Autowired
    private CustomUserDetailService customUserDetailService;
    @Autowired
    private LogoutSuccessHandler customLogoutHandler;

    @Autowired
    public void globalUserDetails(final AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailService).passwordEncoder(passwordEncoder);
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        // @formatter:off
        http.httpBasic()
                .and()
                .authorizeRequests()
                .antMatchers("/oauth/token/revokeById/**").permitAll()
                .antMatchers("/login", "/oauth/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .logout()
                .logoutSuccessHandler(customLogoutHandler)
                .deleteCookies("JSESSIONID")
                .permitAll()
                .and()
                .formLogin().permitAll()
                .and()
                .csrf().disable();
        // @formatter:on
    }

}
