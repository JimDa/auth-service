package com.example.auth.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface IUserAccountService extends UserDetailsService {
    UserDetails loadUserByPhoneNum(String phoneNum);
}
