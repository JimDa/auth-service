package com.example.auth.service;

import com.example.auth.mapper.UserAccountMapper;
import dto.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserAccountServiceImpl implements IUserAccountService {
    @Autowired
    private UserAccountMapper userAccountMapper;

    @Override
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        User user = userAccountMapper.selectByUsername(name);
        if (null == user) {
            throw new UsernameNotFoundException(name);
        }
        return user;
    }
}
