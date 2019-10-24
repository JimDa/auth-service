package com.example.auth;

import com.google.common.collect.Maps;
import domain.User;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;

public class CustomTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
        HashMap<String, Object> map = Maps.newHashMap();
        final Object obj = oAuth2Authentication.getUserAuthentication().getDetails();
        if (obj instanceof User) {
            User user = (User) obj;
            map.put("user_id", user.getId());
            map.put("user_name", user.getUsername());
        }

        ((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(map);
        return oAuth2AccessToken;
    }
}
