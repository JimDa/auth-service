package com.example.auth.endpoints;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
@RequestMapping(value = "/oauth/token")
public class TokenRevokeEndpoint {
    @Resource(name = "defaultTokenServices")
    private ConsumerTokenServices tokenServices;

    @PostMapping(value = "/revoke-by-id/{tokenId}")
    public ResponseEntity<Boolean> revokeToken(@PathVariable String tokenId) {
        boolean result = tokenServices.revokeToken(tokenId);
        return ResponseEntity.ok(result);
    }
}
