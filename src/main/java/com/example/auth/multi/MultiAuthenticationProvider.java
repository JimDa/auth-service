package com.example.auth.multi;

import com.example.auth.service.IUserAccountService;
import domain.User;
import lombok.Data;
import multi.MultiAuthenticationToken;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author dpc
 */
@Data
public class MultiAuthenticationProvider implements AuthenticationProvider {
    public static final String LOGIN_TYPE_USERNAME = "username";
    public static final String LOGIN_TYPE_MOBILE = "phone_num";
    public static final String LOGIN_TYPE_EMAIL = "email";
    public static final String LOGIN_TYPE_VERIFY_CODE = "verify_code";
    private StringRedisTemplate stringRedisTemplate;
    private IUserAccountService iUserAccountService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MultiAuthenticationToken token = (MultiAuthenticationToken) authentication;
        String loginType = (String) token.getLoginType();
        String principal = (String) token.getPrincipal();
        String credentials = (String) token.getCredentials();
        User user = iUserAccountService.loadUserByLoginType(loginType, principal);
        if (null == user) {
            throw new InternalAuthenticationServiceException("无法获取用户信息！");
        }
        switch (loginType) {
            case "username":
                if (!bCryptPasswordEncoder.matches(credentials, user.getPassword())) {
                    throw new BadCredentialsException("密码错误！");
                }
                break;
            case "phone_num":
                if (!bCryptPasswordEncoder.matches(credentials, user.getPassword())) {
                    throw new BadCredentialsException("密码错误！");
                }
                break;
            case "email":
                if (!bCryptPasswordEncoder.matches(credentials, user.getPassword())) {
                    throw new BadCredentialsException("密码错误！");
                }
                break;
            case "verify_code":
                String code = stringRedisTemplate.opsForValue().get("ALI_SMS:".concat(principal));
                if (!credentials.equals(code)) {
                    throw new BadCredentialsException("密码错误！");
                }

        }
        MultiAuthenticationToken authenticatedToken = new MultiAuthenticationToken(principal, user.getAuthorities());
        return authenticatedToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MultiAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
