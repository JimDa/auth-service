package com.example.auth.multi;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author dpc
 */
public class MultiAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    public static final String CREDENTIAL_KEY = "credential";
    public static final String PRINCIPAL_KEY = "principal";
    public static final String LOGIN_TYPE_KEY = "login_type";
    private Boolean postOnly = true;

    public MultiAuthenticationFilter() {
        super(new AntPathRequestMatcher("/oauth/token"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
        if (postOnly && httpServletRequest.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + httpServletRequest.getMethod());
        }

        String principal = obtainPrincipal(httpServletRequest);
        String credential = obtainCredential(httpServletRequest);
        String loginType = obtainLoginType(httpServletRequest);
        MultiAuthenticationToken token = new MultiAuthenticationToken(principal, credential, loginType);
        this.setDetails(httpServletRequest, token);
        return this.getAuthenticationManager().authenticate(token);
    }

    private void setDetails(HttpServletRequest httpServletRequest, MultiAuthenticationToken token) {
        token.setDetails(this.authenticationDetailsSource.buildDetails(httpServletRequest));
    }

    private String obtainPrincipal(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter(PRINCIPAL_KEY);
    }

    private String obtainCredential(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter(CREDENTIAL_KEY);
    }

    private String obtainLoginType(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter(LOGIN_TYPE_KEY);
    }
}
