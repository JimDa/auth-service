package com.example.auth.mapper;

import dto.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface UserAccountMapper {
    User selectByUsername(@Param("username") String username);
}
