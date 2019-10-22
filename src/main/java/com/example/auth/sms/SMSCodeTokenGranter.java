package com.example.auth.sms;

import com.example.auth.exception.UserPhoneNumNotFoundException;
import com.example.auth.service.IUserAccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.Map;

public class SMSCodeTokenGranter extends AbstractTokenGranter {
    public static final String GRANT_TYPE = "sms_code";
    @Autowired
    private IUserAccountService iUserAccountService;
    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    protected SMSCodeTokenGranter(AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory, String grantType) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails clientDetails, TokenRequest tokenRequest) {
        Map<String, String> parameters = tokenRequest.getRequestParameters();
        String phoneNum = parameters.get("phoneNum");
        String verifyCode = parameters.get("verifyCode");
        UserDetails user = iUserAccountService.loadUserByPhoneNum(phoneNum);
        if (null == user) {
            throw new UserPhoneNumNotFoundException("用户不存在！");
        }

        String aliVerifyCode = stringRedisTemplate.opsForValue().get("ALI_SMS:".concat(phoneNum));
        if (!verifyCode.equals(aliVerifyCode)) {
            throw new InvalidGrantException("验证码不正确！");
        } else {
            stringRedisTemplate.delete("ALI_SMS:".concat(phoneNum));
        }

        Authentication userAuth = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        ((AbstractAuthenticationToken) userAuth).setDetails(parameters);
        OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(clientDetails, tokenRequest);
        return new OAuth2Authentication(storedOAuth2Request, userAuth);
    }
}
