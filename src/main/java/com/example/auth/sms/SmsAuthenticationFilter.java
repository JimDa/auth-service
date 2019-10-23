package com.example.auth.sms;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SmsAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    public static final String MOBILE_KEY = "mobile";
    private String mobileParameter = MOBILE_KEY;
    private boolean postOnly = true;

    public SmsAuthenticationFilter() {
        super(new AntPathRequestMatcher("/oauth/login/mobile"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
        if (postOnly && !httpServletRequest.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + httpServletRequest.getMethod());
        }

        String mobile = obtainMobile(httpServletRequest);
        String verifyCode = obtainVerifyCode(httpServletRequest);
        String trimMobile = mobile.trim();
        SmsAuthenticationToken token = new SmsAuthenticationToken(trimMobile, verifyCode);
        this.setDetails(httpServletRequest, token);
        return this.getAuthenticationManager().authenticate(token);
    }

    private void setDetails(HttpServletRequest httpServletRequest, SmsAuthenticationToken token) {
        token.setDetails(this.authenticationDetailsSource.buildDetails(httpServletRequest));
    }

    private String obtainVerifyCode(HttpServletRequest httpServletRequest) {
        String verifyCode = httpServletRequest.getParameter("verifyCode");
        return StringUtils.isEmpty(verifyCode) ? "" : verifyCode;
    }

    private String obtainMobile(HttpServletRequest httpServletRequest) {
        String mobile = httpServletRequest.getParameter(mobileParameter);
        return StringUtils.isEmpty(mobile) ? "" : mobile;
    }
}
