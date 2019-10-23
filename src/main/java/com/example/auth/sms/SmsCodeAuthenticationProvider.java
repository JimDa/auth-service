package com.example.auth.sms;

import com.example.auth.service.IUserAccountService;
import domain.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SmsCodeAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private StringRedisTemplate stringRedisTemplate;
    private IUserAccountService iUserAccountService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        SmsAuthenticationToken smsAuthenticationToken = (SmsAuthenticationToken) authentication;
        User user = iUserAccountService.loadUserByPhoneNum((String) smsAuthenticationToken.getPrincipal());
        if (null == user) {
            throw new InternalAuthenticationServiceException("无法获取用户信息！");
        }
        String verifyCode = stringRedisTemplate.opsForValue().get("ALI_SMS:".concat(user.getPhoneNum()));
        if (!smsAuthenticationToken.getCredentials().equals(verifyCode)) {
            throw new InternalAuthenticationServiceException("验证码填写错误！");
        }
        SmsAuthenticationToken authenticatedToken = new SmsAuthenticationToken(user.getPhoneNum(), user.getAuthorities());
        authenticatedToken.setDetails(smsAuthenticationToken.getDetails());
        return authenticatedToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SmsAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
