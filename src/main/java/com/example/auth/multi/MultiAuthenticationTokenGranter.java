package com.example.auth.multi;

import com.example.auth.service.IUserAccountService;
import domain.User;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;

import java.util.LinkedHashMap;
import java.util.Map;

public class MultiAuthenticationTokenGranter extends AbstractTokenGranter {
    private static final String GRANT_TYPE = "multi";
    private final AuthenticationManager authenticationManager;
    private IUserAccountService iUserAccountService;
    private DefaultTokenServices defaultTokenServices;

    public MultiAuthenticationTokenGranter(AuthenticationManager authenticationManager, AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory, IUserAccountService iUserAccountService, DefaultTokenServices defaultTokenServices) {
        this(authenticationManager, tokenServices, clientDetailsService, requestFactory, GRANT_TYPE, iUserAccountService, defaultTokenServices);
    }

    protected MultiAuthenticationTokenGranter(AuthenticationManager authenticationManager, AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory, String grantType, IUserAccountService iUserAccountService, DefaultTokenServices defaultTokenServices) {
        super(tokenServices, clientDetailsService, requestFactory, grantType);
        this.authenticationManager = authenticationManager;
        this.iUserAccountService = iUserAccountService;
        this.defaultTokenServices = defaultTokenServices;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        Map<String, String> parameters = new LinkedHashMap(tokenRequest.getRequestParameters());
        String username = (String) parameters.get("username");
        String password = (String) parameters.get("password");
        String loginType = parameters.get("login_type");
        parameters.remove("password");
        Authentication userAuth = new MultiAuthenticationToken(username, password, loginType);
        User user = iUserAccountService.loadUserByLoginType(loginType, username);
        ((AbstractAuthenticationToken) userAuth).setDetails(user);

        try {
            userAuth = this.authenticationManager.authenticate(userAuth);
        } catch (AccountStatusException var8) {
            throw new InvalidGrantException(var8.getMessage());
        } catch (BadCredentialsException var9) {
            throw new InvalidGrantException(var9.getMessage());
        }

        if (userAuth != null && userAuth.isAuthenticated()) {
            OAuth2Request storedOAuth2Request = this.getRequestFactory().createOAuth2Request(client, tokenRequest);
            return new OAuth2Authentication(storedOAuth2Request, userAuth);
        } else {
            throw new InvalidGrantException("Could not authenticate user: " + username);
        }
    }

    @Override
    protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
        return this.defaultTokenServices.createAccessToken(this.getOAuth2Authentication(client, tokenRequest));
    }
}
