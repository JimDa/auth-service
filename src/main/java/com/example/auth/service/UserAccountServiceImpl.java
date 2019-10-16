package com.example.auth.service;

import com.example.auth.clients.UserClient;
import dto.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserAccountServiceImpl implements IUserAccountService {
    @Autowired
    private UserClient userClient;

    @Override
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        ResponseEntity<User> response = userClient.queryUserByName(name);
        if (response.getStatusCodeValue() != 200 && null == response.getBody()) {
            throw new UsernameNotFoundException(name);
        }
        return response.getBody();
    }
}
