package com.example.auth.config;

import com.example.auth.multi.MultiAuthenticationSecurityConfig;
import com.example.auth.service.IUserAccountService;
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
    private IUserAccountService iUserAccountService;
    @Autowired
    private LogoutSuccessHandler customLogoutHandler;
    @Autowired
    private MultiAuthenticationSecurityConfig multiAuthenticationSecurityConfig;

    @Autowired
    public void globalUserDetails(final AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(iUserAccountService).passwordEncoder(passwordEncoder);
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        // @formatter:off
        http.formLogin()
//                .loginPage("/login/page")
//                .loginProcessingUrl("/login/process")
                .and()
                .authorizeRequests()
                .antMatchers("/actuator/**").permitAll()
                .antMatchers("/oauth/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .apply(multiAuthenticationSecurityConfig)
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
