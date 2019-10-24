package com.example.auth.multi;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

import java.util.Collection;

/**
 * @author dpc
 */
public class MultiAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    private final Object principal;
    private Object credentials;
    private Object loginType;

    public MultiAuthenticationToken(Object principal, Object credentials, Object loginType) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        this.loginType = loginType;
        super.setAuthenticated(false);
    }

    public MultiAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
    }

    public Object getLoginType() {
        return this.loginType;
    }
}
