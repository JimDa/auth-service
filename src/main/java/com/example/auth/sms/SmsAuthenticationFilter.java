//package com.example.auth.sms;
//
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//
//import javax.servlet.ServletException;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import java.io.IOException;
//
//public class SmsAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
//    public static final String MOBILE_KEY = "mobile";
//    private String mobileParameter = MOBILE_KEY;
//    private boolean postOnly =true;
//
//    public SmsAuthenticationFilter() {
//        super(new AntPathRequestMatcher());
//    }
//
//    @Override
//    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
//        return null;
//    }
//}
