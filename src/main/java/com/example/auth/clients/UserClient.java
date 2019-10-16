package com.example.auth.clients;


import dto.User;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "user-service", url = "http://127.0.0.1:8082/user-service", path = "/user")
public interface UserClient {
    @GetMapping(value = "/query-user-by-name")
    ResponseEntity<User> queryUserByName(@RequestParam("userName") String userName);
}
