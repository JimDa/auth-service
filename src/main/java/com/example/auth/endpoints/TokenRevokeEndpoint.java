package com.example.auth.endpoints;

import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
public class TokenRevokeEndpoint {
    @Resource(name = "defaultTokenServices")
    private ConsumerTokenServices tokenServices;


    @RequestMapping(method = RequestMethod.POST, value = "/oauth/token/revokeById/{tokenId}")
    public void revokeToken(@PathVariable String tokenId) {
        tokenServices.revokeToken(tokenId);
    }
}
