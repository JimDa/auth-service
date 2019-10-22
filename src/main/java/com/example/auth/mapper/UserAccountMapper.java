package com.example.auth.mapper;

import domain.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface UserAccountMapper {
    User selectByUsername(@Param("username") String username);

    User selectByPhoneNum(@Param("phoneNum") String phoneNum);
}
